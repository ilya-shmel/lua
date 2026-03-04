local template = [[
{{.Meta.alert_title}}

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{.Meta.observer_ip}}
Хост: {{.Meta.observer_hostname}}
FQDN: {{.Meta.observer_fqdn}}

ИНИЦИАТОР:
Пользователь: {{.Meta.user_name}}
UID: {{.Meta.user_id}}
Процесс: {{.Meta.process_path}}

ВЫПОЛНЕННАЯ КОМАНДА:
{{.Meta.command}}
]]

local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

local log_path =
    "(?:\\/var\\/(?:log|lib)|(?:~|[\\/\\w\\-_]+\\/home|\\/root)\\/\\.(?:local\\/share|cache|config)|\\/(?:opt|srv)[\\/\\w\\-_\\*]+\\/log(s))(\\/[\\/\\w\\-_\\*]+(\\.log)?)?"

local threats = {{
    pattern = "rm\\s+(?:[-\\w\\s=]+)+" .. log_path,
    name = "Обнаружено удаление журналов аудита.",
    risk = 9.0,
    mitre = {"T1562", "T1562.001"}
}, {
    pattern = "auditctl\\s+-D",
    name = "Обнаружена очистка правил аудита (auditctl -D).",
    risk = 9.0,
    mitre = {"T1562", "T1562.008"}
}, {
    pattern = "truncate\\s+(?:[-a-z\\d\\s=]+)+" .. log_path,
    name = "Подозрение на очистку журналов аудита.",
    risk = 8.5,
    mitre = {"T1562.001"}
}, {
    pattern = "unlink\\s+" .. log_path,
    name = "Подозрение на перезапись журналов аудита.",
    risk = 8.0,
    mitre = {"T1562.001"}
}, {
    pattern = "find\\s+" .. log_path ..
        "[\\-\\w\\s+]+-exec\\s+(?:sh|truncate)\\s+[\\-a-z\\d\\s_>\"$]+\\{\\}\\s*(?:;|\\+)?",
    name = "Подозрение на очистку журналов аудита.",
    risk = 8.5,
    mitre = {"T1562.001"}
}, {
    pattern = "journalctl\\s+--vacuum",
    name = "Обнаружена очистка журналов journalctl.",
    risk = 7.5,
    mitre = {"T1562", "T1562.001"}
}, {
    pattern = "systemctl\\s+(?:stop|disable|mask|kill)\\s+systemd-journald",
    name = "Обнаружена попытка отключения журналирования systemd-journald.",
    risk = 8.5,
    mitre = {"T1562", "T1562.001"}
}, {
    pattern = "sed\\s+.*-i.*journald(?:\\.conf)?.*storage\\s*=",
    name = "Обнаружена модификация конфигурации systemd-journald.",
    risk = 8.0,
    mitre = {"T1562", "T1562.001"}
}, {
    pattern = "(?:systemctl\\s+(?:stop|disable)\\s+auditd(?:\\.service)?$|service\\s+auditd\\s+stop|auditctl\\s+[-ed])",
    name = "Обнаружена попытка отключения подсистемы аудита (auditd).",
    risk = 9.5,
    mitre = {"T1562", "T1562.008"}
}, {
    pattern = "setenforce\\s+(?:0|Permissive)",
    name = "Обнаружена попытка отключения SELinux.",
    risk = 8.0,
    mitre = {"T1562", "T1562.001"}
}, {
    pattern = "(?:systemctl\\s+(?:stop|disable)\\s+apparmor|aa-disable)",
    name = "Обнаружена попытка отключения AppArmor.",
    risk = 8.0,
    mitre = {"T1562", "T1562.001"}
}, {
    pattern = "(?:systemctl\\s+(?:stop|disable)\\s+(?:ufw|firewalld)|ufw\\s+disable|iptables\\s+[-FXP])",
    name = "Обнаружена попытка отключения брандмауэра.",
    risk = 8.5,
    mitre = {"T1562", "T1562.004"}
}, {
    pattern = "sed\\s+.*-i.*(?:PermitRootLogin\\s*=\\s*yes|PasswordAuthentication\\s*=\\s*yes)",
    name = "Обнаружена попытка ослабления конфигурации SSH.",
    risk = 7.0,
    mitre = {"T1556"}
}, {
    pattern = "(?:sed\\s+.*-i.*NOPASSWD|echo\\s+.*NOPASSWD.*>>)",
    name = "Обнаружена попытка добавления NOPASSWD в sudoers.",
    risk = 8.5,
    mitre = {"T1548"}
}, {
    pattern = "systemctl\\s+(?:stop|disable)\\s+(?:cron|crond)",
    name = "Обнаружена попытка отключения cron.",
    risk = 6.5,
    mitre = {"T1562"}
}, {
    pattern = "(?:systemctl\\s+(?:stop|disable)\\s+rsyslog|service\\s+rsyslog\\s+stop|kill\\s+.*rsyslog)",
    name = "Обнаружена попытка отключения rsyslog.",
    risk = 8.5,
    mitre = {"T1562", "T1562.001"}
}, {
    pattern = "(?:systemctl\\s+(?:stop|disable)\\s+syslog-ng|kill\\s+.*syslog-ng)",
    name = "Обнаружена попытка отключения syslog-ng.",
    risk = 8.5,
    mitre = {"T1562", "T1562.001"}
}, {
    pattern = "(?:sed|nano|vim|vi|emacs|pico|joe|echo|cat|tee|cp|mv|ln|chmod|chown|awk)\\s+.*(?:/etc/audit/|/etc/libudit/)",
    name = "Обнаружена модификация конфигурации аудита.",
    risk = 8.5,
    mitre = {"T1562", "T1562.008"}
}, {
    pattern = "exec\\s+\\d+>",
    name = "Обнаружено перенаправление файловых дескрипторов логирования.",
    risk = 7.5,
    mitre = {"T1562"}
}, {
    pattern = "(?:sed|nano|vim|vi|emacs|pico|joe|echo|cat|tee|cp|mv|ln|chmod|chown|awk)\\s+.*(?:/etc/rsyslog|/etc/syslog-ng|syslog\\.conf)",
    name = "Обнаружено изменение в конфигурационных файлах системы логирования.",
    risk = 8.5,
    mitre = {"T1562", "T1562.002", "T1070.003"}
}, {
    pattern = "(?:histsize\\s*=\\s*0|histfilesize\\s*=\\s*0|histcontrol\\s*=\\s*ignore|unset\\s+histfile)",
    name = "Обнаружено отключение журналирования команд shell.",
    risk = 7.0,
    mitre = {"T1562.003"}
}, {
    pattern = "(?:systemctl\\s+(?:stop|disable|mask)\\s+auditd(?:\\.service)?$|pkill\\s+(?:-9\\s+)?(?:auditd|audispd)|service\\s+auditd\\s+stop|auditctl\\s+(?:-D|-e\\s+0|-d|-l|-w|-R)|(?:sed|nano|echo|truncate|vi|emacs|gedit|rm)\\s+.*(?:/etc/audit/))",
    name = "Обнаружено отключение или перенастройка системы аудита Linux.",
    risk = 9.5,
    mitre = {"T1562", "T1562.012"}
}}

local fp_patterns = {"apt-get|dpkg|test|grep|man|help|ansible|puppet|chef|salt|terraform",
                     "atomic.*red.*team|red.*team|metasploit|caldera|nessus|tenable|qualys|rapid7|burp.*suite|cobalt.*strike|empire|covenant|sliver"}

local service_whitelist = {"dnf-makecache", "apt-daily", "yum-cron", "packagekit",
                           "unattended-upgrades", "snapd\\.refresh", "fwupd-refresh"}

local critical_services = {"auditd", "firewalld", "apparmor", "rsyslog", "syslog-ng",
                           "systemd-journald"}

local bin_pattern = "\\/?r?syslog(-ng)?"
local file_pattern =
    "(?:[-\\w]+\\.log|apt|audit\\.log|(?:b|w)tmp|(?:fail|last|sys)log|installer|journal|private|runit|secure|sssd)((\\.\\d+(\\.\\wz)?))?"

local function is_false_positive(cmd)
    local cmd_lower = cmd:lower()
    for _, pattern in ipairs(fp_patterns) do
        if cmd_lower:search(pattern) then
            return true
        end
    end
    return false
end

local function is_whitelisted_service(service_name)
    service_name = service_name:lower() 
    for _, pattern in ipairs(service_whitelist) do
        if service_name:search(pattern) then
            return true
        end
    end
    return false
end

local function is_critical_service(service_name)
    service_name = service_name:lower()
    for _, pattern in ipairs(critical_services) do
        if service_name:search(pattern) then
            return true
        end
    end
    return false
end

local function analyze_threat(cmd)
    cmd = cmd:lower()
    if is_false_positive(cmd) then
        return nil
    end
    for i, threat in ipairs(threats) do
        if cmd:search(threat.pattern) then
            return i
        end
    end
end

local function fire_alert(idx, user_name, user_id, process_path, command, log_exec, log_sys, events)
    local threat = threats[idx]
    local source = log_sys or log_exec
    alert({
        template = template,
        meta = {
            alert_title = threat.name,
            observer_ip = source:gets("observer.host.ip") or "unknown",
            observer_hostname = source:gets("observer.host.hostname") or "unknown",
            observer_fqdn = source:gets("observer.host.fqdn") or "unknown",
            user_name = user_name,
            user_id = user_id,
            process_path = process_path,
            command = command
        },
        risk_level = threat.risk,
        asset_ip = source:get_asset_data("observer.host.ip"),
        asset_hostname = source:get_asset_data("observer.host.hostname"),
        asset_fqdn = source:get_asset_data("observer.host.fqdn"),
        asset_mac = "",
        create_incident = true,
        incident_group = "Defense Evasion",
        assign_to_customer = false,
        incident_identifier = "",
        logs = events,
        mitre = threat.mitre,
        trim_logs = 10
    })
end

function on_logline(logline)
    local event_type = logline:gets("observer.event.type")

    if event_type == "EXECVE" or event_type == "PROCTITLE" then
        local command = logline:gets("initiator.command.executed")
        if command and analyze_threat(command) then
            grouper1:feed(logline)
        end
    elseif event_type == "SYSCALL" then
        local syscall = logline:gets("target.syscall.name")
        if syscall == "execve" then
            grouper1:feed(logline)
        elseif syscall == "257" or syscall == "1" or syscall == "2" or syscall == "76" then
            local path = logline:gets("initiator.process.path.name")
            if not (path and path:search(bin_pattern)) then
                grouper1:feed(logline)
            end
        end
    elseif event_type == "PATH" then
        local file_path = logline:gets("target.object.path.full")
        if file_path and (file_path:search(log_path) or file_path:search(file_pattern)) then
            grouper1:feed(logline)
        end
    elseif event_type == "SERVICE_STOP" or event_type == "SERVICE_DISABLE" then
        local service_name = logline:gets("target.service.name")
        if service_name and is_critical_service(service_name) then
            grouper1:feed(logline)
        end
    end
end

function on_grouped(grouped)
    if grouped.aggregatedData.unique.total >= 1 then
        local events = grouped.aggregatedData.loglines
        local log_exec, log_sys, log_path, log_service

        for _, event in ipairs(events) do
            local etype = event:gets("observer.event.type")
            if etype == "SYSCALL" then
                log_sys = event
            elseif etype == "EXECVE" or etype == "PROCTITLE" then
                log_exec = event
            elseif etype == "PATH" then
                log_path = event
            elseif etype == "SERVICE_STOP" or etype == "SERVICE_DISABLE" then
                log_service = event
            end
        end

        if log_service then
            local service_name = log_service:gets("target.service.name") or "unknown"
            if not is_whitelisted_service(service_name) and is_critical_service(service_name) then
                local command = "systemctl stop " .. service_name
                if not is_false_positive(command) then
                    fire_alert(22, log_service:gets("initiator.user.name") or "systemd",
                        log_service:gets("initiator.user.id") or "0",
                        log_service:gets("initiator.process.path.full") or "/usr/lib/systemd/systemd", command,
                        log_service, log_service, events)
                end
            end
        elseif log_sys and log_exec and log_path and grouped.aggregatedData.unique.total > 1 then
            local command = log_exec:gets("initiator.command.executed")
            if command then
                local idx = analyze_threat(command)
                if idx then
                    fire_alert(idx, log_sys:gets("initiator.user.name") or "unknown",
                        log_sys:gets("initiator.user.id") or "0",
                        log_sys:gets("initiator.process.path.full") or "unknown", command, log_exec, log_sys, events)
                end
            end
        elseif log_exec then
            local command = log_exec:gets("initiator.command.executed")
            if command then
                local idx = analyze_threat(command)
                if idx then
                    fire_alert(idx, log_sys and log_sys:gets("initiator.user.name") or "unknown",
                        log_sys and log_sys:gets("initiator.user.id") or "0",
                        log_sys and log_sys:gets("initiator.process.path.full") or "unknown", command, log_exec,
                        log_sys, events)
                end
            end
        end
    end
    grouper1:clear()
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)
