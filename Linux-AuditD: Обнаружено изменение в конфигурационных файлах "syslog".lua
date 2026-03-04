local detection_window = "120s"
local create_incident = true
local assign_to_customer = false
local base_risk_score = 8.0

local grouped_by = { "observer.host.ip", "observer.host.hostname", "initiator.user.id", "initiator.user.name" }
local aggregated_by = { "initiator.command.executed", "target.file.path", "target.process.path.full", "raw",
    "event.description" }
local grouped_time_field = "@timestamp,RFC3339Nano"

local logging_files = {
    "/etc/syslog.conf", "/etc/rsyslog.conf", "/etc/rsyslog.d/", "/etc/syslog-ng/syslog-ng.conf",
    "/etc/syslog-ng.conf", "/var/log/syslog", "/var/log/messages", "/var/log/kern.log",
    "/etc/audit/auditd.conf", "/etc/audit/rules.d/", "/etc/audit/audit.rules",
    "/var/log/audit/audit.log", "/etc/systemd/journald.conf", "/var/log/journal/",
    "/.bash_history", "/.zsh_history", "/.ksh_history", "/.history", "/.sh_history",
    "/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/.bashrc", "/.bash_profile",
    "/.zshrc", "/.profile", "/.zprofile", "/.zshenv", "/.inputrc",
    "/etc/pam.conf", "/etc/pam.d/", "/etc/security/pam_env.conf",
    "/var/log/auth.log", "/var/log/secure", "/var/log/wtmp", "/var/log/lastlog",
    "/var/log/utmp", "/var/log/btmp", "/var/log/faillog", "/var/log/sulog"
}

local disable_commands = {
    "history -c", "history -w", "history -r", "history -d", "history -a",
    "unset HISTFILE", "export HISTFILE=/dev/null", "export HISTFILE=\"\"", "export HISTFILE=",
    "export HISTSIZE=0", "export HISTFILESIZE=0", "HISTCONTROL=ignorespace", "HISTCONTROL=ignoredups",
    "HISTCONTROL=ignoreboth", "HISTCONTROL=erasedups", "HISTIGNORE=", "export HISTIGNORE=",
    "systemctl stop rsyslog", "systemctl disable rsyslog", "systemctl mask rsyslog",
    "systemctl stop auditd", "systemctl disable auditd", "systemctl mask auditd",
    "systemctl stop systemd-journald", "systemctl disable systemd-journald", "systemctl mask systemd-journald",
    "systemctl stop syslog", "systemctl disable syslog", "systemctl mask syslog",
    "service rsyslog stop", "service auditd stop", "service syslog stop", "service syslog-ng stop",
    "/etc/init.d/rsyslog stop", "/etc/init.d/auditd stop", "/etc/init.d/syslog stop",
    "/etc/init.d/syslog-ng stop", "pkill rsyslog", "pkill auditd", "pkill syslog-ng",
    "auditctl -e 0", "auditctl -D", "auditctl --delete-all", "auditctl --remove-all",
    "auditctl -b 0", "auditctl -d", "auditctl -R /dev/null", "auditctl --reset-lost",
    "truncate -s 0", "truncate --size=0", "dd if=/dev/null of=", "echo -n >", "> /var/log/",
    "cat /dev/null >", "cat /dev/zero >", "rm -f /var/log/", "rm -rf /var/log/",
    "shred -vfz", "shred -n 3 -z -u", "wipe -rf", "srm -rf", "rm -P"
}

local evasion_patterns = {
    "set +o history", "set +H", "bash --norc", "sh --norc", "zsh --no-rcs",
    "bash -c 'set +o history'", "sh -c 'set +o history'", "exec bash --norc",
    "ln -sf /dev/null", "mount -t tmpfs", "chattr +i", "chattr -i", "immutable",
    "history -d ", "export PS1=", "export PROMPT_COMMAND=", "unset PROMPT_COMMAND",
    "shopt -ou history", "shopt -uo history", "HISTTIMEFORMAT=", "export HISTTIMEFORMAT="
}

local advanced_patterns = {
    "sed -i '/.*history.*/d'", "awk 'BEGIN{system(\"history -c\")}'",
    "perl -e 'system(\"history -c\")'", "python -c 'import os; os.system(\"history -c\")'",
    "exec 1>/dev/null 2>&1", "exec >/dev/null 2>&1", "nohup", "disown",
    "logger -p local0.info", "wall", "write", "mesg n", "script -q /dev/null",
    "/tmp/.history", "/var/tmp/.history", "/dev/shm/.history"
}

local template = [[T1562.003: Обнаружено отключение или модификация регистрации команд

Узел: {{ .First.observer.host.ip }} - {{ .First.observer.host.hostname }}
Пользователь: {{ if .First.initiator.user.name }}{{ .First.initiator.user.name }}{{ else }}{{ .First.initiator.user.id }}{{ end }}
Команда: {{ .First.initiator.command.executed }}

АНАЛИЗ АТАКИ:
Тип атаки: {{ .Meta.attack_type }}
Метод отключения: {{ .Meta.disable_method }}
Затронутые компоненты: {{ .Meta.affected_components }}

ДЕТАЛИ ОБНАРУЖЕНИЯ:
{{ .Meta.detection_details }}

Всего событий: {{ .Meta.total_events }}]]

local function contains_pattern(text, patterns)
    if not text or text == "" then return false, "" end
    local text_lower = text:lower()
    for _, pattern in ipairs(patterns) do
        if text_lower:find(pattern:lower(), 1, true) then
            return true, pattern
        end
    end
    return false, ""
end

local function extract_operations(command, file_path)
    local ops = {}
    if not command and not file_path then return ops end

    local combined = (command or "") .. " " .. (file_path or "")
    local lower_text = combined:lower()

    if lower_text:find("truncate") or lower_text:find("echo.*>") then
        table.insert(ops, "File Truncation")
    end
    if lower_text:find("rm") or lower_text:find("unlink") or lower_text:find("del") then
        table.insert(ops, "File Deletion")
    end
    if lower_text:find("shred") or lower_text:find("wipe") or lower_text:find("srm") then
        table.insert(ops, "Secure File Erasure")
    end
    if lower_text:find("chattr") or lower_text:find("chmod") then
        table.insert(ops, "File Attribute Modification")
    end
    if lower_text:find("systemctl") or lower_text:find("service") or lower_text:find("/etc/init.d/") then
        table.insert(ops, "Service Management")
    end
    if lower_text:find("mount") or lower_text:find("umount") then
        table.insert(ops, "Filesystem Operations")
    end
    if lower_text:find("kill") or lower_text:find("pkill") or lower_text:find("killall") then
        table.insert(ops, "Process Termination")
    end

    return ops
end

local function analyze_attack_comprehensive(command, file_path, process_path, raw_data, event_desc)
    local attack = {
        attack_type = "Command History Logging Impairment",
        disable_method = "Unknown Method",
        affected_components = {},
        detection_details = {},
        risk_score = 0
    }

    local context = (command or "") .. " " .. (file_path or "") .. " " ..
        (process_path or "") .. " " .. (raw_data or "") .. " " .. (event_desc or "")

    local has_logging_file, matched_file = contains_pattern(context, logging_files)
    local has_disable_cmd, matched_cmd = contains_pattern(command, disable_commands)
    local has_evasion, matched_evasion = contains_pattern(command, evasion_patterns)
    local has_advanced, matched_advanced = contains_pattern(command, advanced_patterns)

    if has_logging_file then
        table.insert(attack.affected_components, matched_file)
        attack.risk_score = attack.risk_score + 3
        table.insert(attack.detection_details, "Access to logging infrastructure detected")
    end

    if has_disable_cmd then
        attack.disable_method = "Direct Command: " .. matched_cmd
        attack.risk_score = attack.risk_score + 6
        table.insert(attack.detection_details, "Explicit disable command executed")

        if matched_cmd:find("history") then
            attack.attack_type = "Shell Command History Disable"
        elseif matched_cmd:find("auditctl") or matched_cmd:find("auditd") then
            attack.attack_type = "Linux Audit System Disable"
        elseif matched_cmd:find("syslog") or matched_cmd:find("rsyslog") then
            attack.attack_type = "System Logging Service Disable"
        elseif matched_cmd:find("systemd-journald") then
            attack.attack_type = "Systemd Journal Disable"
        end
    end

    if has_evasion then
        attack.disable_method = "Evasion Technique: " .. matched_evasion
        attack.risk_score = attack.risk_score + 5
        table.insert(attack.detection_details, "Advanced evasion technique detected")

        if matched_evasion:find("set +o history") then
            attack.attack_type = "Shell History Evasion"
        elseif matched_evasion:find("--norc") then
            attack.attack_type = "Shell Resource File Bypass"
        end
    end

    if has_advanced then
        attack.disable_method = "Advanced Method: " .. matched_advanced
        attack.risk_score = attack.risk_score + 4
        table.insert(attack.detection_details, "Sophisticated attack pattern identified")

        if matched_advanced:find("script") or matched_advanced:find("perl") or matched_advanced:find("python") then
            attack.attack_type = "Scripted History Manipulation"
        end
    end

    local file_ops = extract_operations(command, file_path)
    for _, op in ipairs(file_ops) do
        table.insert(attack.detection_details, op .. " operation detected")
        attack.risk_score = attack.risk_score + 2
    end

    local cmd_lower = (command or ""):lower()
    if cmd_lower:find("export") and (cmd_lower:find("hist") or cmd_lower:find("log")) then
        attack.risk_score = attack.risk_score + 3
        table.insert(attack.detection_details, "Environment variable manipulation detected")
    end

    if cmd_lower:find("/dev/null") or cmd_lower:find("/dev/zero") then
        attack.risk_score = attack.risk_score + 2
        table.insert(attack.detection_details, "Output redirection to null device")
    end

    if cmd_lower:find("tmp") and (cmd_lower:find("history") or cmd_lower:find("log")) then
        attack.risk_score = attack.risk_score + 2
        table.insert(attack.detection_details, "Temporary directory manipulation")
    end

    if cmd_lower:find("nohup") or cmd_lower:find("disown") or cmd_lower:find("&") then
        attack.risk_score = attack.risk_score + 1
        table.insert(attack.detection_details, "Background process execution")
    end

    if not has_disable_cmd and not has_evasion and not has_advanced and has_logging_file then
        attack.disable_method = "File System Access"
        attack.risk_score = attack.risk_score + 2
        table.insert(attack.detection_details, "Suspicious access to logging files")
    end

    return attack
end

function on_logline(logline)
    if not logline then return end

    local command = logline:get("initiator.command.executed", "")
    local file_path = logline:get("target.file.path", "") or logline:get("target.process.path.full", "")
    local process_path = logline:get("initiator.process.path.full", "")
    local raw_data = logline:get("raw", "")
    local event_desc = logline:get("event.description", "")
    local action = logline:get("action", "")
    local event_category = logline:get("event.category", "")
    local event_subcategory = logline:get("event.subcategory", "")

    local should_feed = false

    if contains_pattern(command, disable_commands) then
        should_feed = true
    elseif contains_pattern(command, evasion_patterns) then
        should_feed = true
    elseif contains_pattern(command, advanced_patterns) then
        should_feed = true
    elseif contains_pattern(file_path, logging_files) or contains_pattern(command, logging_files) then
        should_feed = true
    elseif action == "path" and contains_pattern(file_path, logging_files) then
        should_feed = true
    elseif event_desc:find("Triggered to record") and contains_pattern(event_desc, logging_files) then
        should_feed = true
    elseif raw_data ~= "" and (contains_pattern(raw_data, logging_files) or
            contains_pattern(raw_data, disable_commands) or
            contains_pattern(raw_data, evasion_patterns)) then
        should_feed = true
    elseif event_category == "system_operation" and event_subcategory == "process" and
        (contains_pattern(command, logging_files) or contains_pattern(process_path, logging_files)) then
        should_feed = true
    end

    if should_feed then
        grouper1:feed(logline)
    end
end

function on_grouped(grouped)
    if not grouped or not grouped.aggregatedData or not grouped.aggregatedData.loglines then
        grouper1:clear()
        return
    end

    local total_events = #grouped.aggregatedData.loglines
    if total_events == 0 then
        grouper1:clear()
        return
    end

    local max_risk = 0
    local best_attack = nil
    local best_event = nil
    local all_components = {}
    local all_details = {}
    local all_methods = {}

    for _, event in ipairs(grouped.aggregatedData.loglines) do
        local cmd = event:get("initiator.command.executed", "")
        local file_p = event:get("target.file.path", "") or event:get("target.process.path.full", "")
        local proc_p = event:get("initiator.process.path.full", "")
        local raw = event:get("raw", "")
        local desc = event:get("event.description", "")

        local attack = analyze_attack_comprehensive(cmd, file_p, proc_p, raw, desc)

        if attack.risk_score > max_risk then
            max_risk = attack.risk_score
            best_attack = attack
            best_event = event
        end

        for _, comp in ipairs(attack.affected_components) do
            all_components[comp] = true
        end
        for _, detail in ipairs(attack.detection_details) do
            all_details[detail] = true
        end
        if attack.disable_method ~= "Unknown Method" then
            all_methods[attack.disable_method] = true
        end
    end

    if max_risk >= 2 and best_event then
        local final_risk = base_risk_score + (max_risk * 0.1)
        if final_risk > 10.0 then final_risk = 10.0 end

        local components_list = {}
        for comp, _ in pairs(all_components) do
            table.insert(components_list, comp)
        end

        local details_list = {}
        for detail, _ in pairs(all_details) do
            table.insert(details_list, detail)
        end

        local methods_list = {}
        for method, _ in pairs(all_methods) do
            table.insert(methods_list, method)
        end

        local components_text = "System logging and command history mechanisms"
        if #components_list > 0 then
            components_text = table.concat(components_list, ", ")
        end

        local details_text = "Standard logging impairment patterns detected"
        if #details_list > 0 then
            details_text = table.concat(details_list, "; ")
        end

        local methods_text = best_attack.disable_method
        if #methods_list > 1 then
            methods_text = table.concat(methods_list, " | ")
        end

        local meta = {
            technique = "T1562.003",
            attack_type = best_attack.attack_type,
            disable_method = methods_text,
            affected_components = components_text,
            detection_details = details_text,
            total_events = tostring(total_events),
            detection_method = "comprehensive_command_history_impairment_detection",
            severity_category = max_risk >= 8 and "Critical" or max_risk >= 6 and "High" or max_risk >= 4 and "Medium" or
            "Low"
        }

        alert({
            template = template,
            risk_level = final_risk,
            asset_ip = best_event:get_asset_data("observer.host.ip"),
            asset_hostname = best_event:get_asset_data("observer.host.hostname"),
            asset_fqdn = best_event:get_asset_data("observer.host.fqdn"),
            asset_mac = best_event:get_asset_data(""),
            create_incident = create_incident,
            incident_group = "",
            assign_to_customer = assign_to_customer,
            incident_identifier = "",
            logs = grouped.aggregatedData.loglines,
            meta = meta,
            mitre = { "T1562", "T1562.003" },
            trim_logs = 10
        })
    end

    grouper1:clear()
end

grouper1 = grouper.new(
    grouped_by,
    aggregated_by,
    grouped_time_field,
    detection_window,
    on_grouped
)