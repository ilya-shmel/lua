local template = [[
Маскировка процесса через vfork syscall.

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{.Meta.observer_ip}}
Хост: {{.Meta.observer_hostname}}
FQDN: {{.Meta.observer_fqdn}}

ИНИЦИАТОР:
Пользователь: {{.Meta.user_name}}
UID: {{.Meta.user_id}}
Процесс: {{.Meta.process_path}}
PID: {{.Meta.parent_pid}} -> {{.Meta.child_pid}}

ВЫПОЛНЕННАЯ КОМАНДА:
{{.Meta.command}}
]]

local detection_window = "3s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "@timestamp"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

local suspicious_patterns = {"sh\\s+-c\\s+\\./[a-zA-Z0-9]{6,}", "bash\\s+-c\\s+\\./[a-zA-Z0-9]{6,}",
                             "sh\\s+-c\\s+[a-zA-Z0-9/]{1,}\\s+\\|", "bash\\s+-c\\s+[a-zA-Z0-9/]{1,}\\s+\\|",
                             "sh\\s+-c\\s+\\$\\{.*\\}", "bash\\s+-c\\s+\\$\\{.*\\}", "\\./[a-zA-Z0-9]{8,}",
                             "\\$\\(.*\\)", "exec\\s+", ">\\s*/dev/null"}

local legitimate_patterns = {"ansible", "puppet", "chef", "salt", "docker", "kubernetes", "systemd", "cron", "scripts"}

local function match_pattern(text, patterns)
    local text_lower = text:lower()
    for _, pattern in ipairs(patterns) do
        if text_lower:search(pattern) then
            return true
        end
    end
    return false
end

local function is_legitimate(cmd)
    return match_pattern(cmd, legitimate_patterns)
end

local function analyze(cmd)
    if is_legitimate(cmd) then
        return false
    end

    return match_pattern(cmd, suspicious_patterns)
end

function on_logline(logline)
    local event_type = logline:gets("observer.event.type") or ""

    if event_type == "SYSCALL" then
        if logline:gets("target.syscall.name") == "vfork" then
            grouper1:feed(logline)
        end
    elseif event_type == "EXECVE" then
        local cmd = logline:gets("initiator.command.executed") or ""
        if analyze(cmd) then
            grouper1:feed(logline)
        end
    end
end

function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local log_execve = ""
    local log_vfork = ""
    local vfork_count = 0

    for _, log in ipairs(events) do
        local event_type = log:gets("observer.event.type") or ""
        if event_type == "SYSCALL" and log:gets("target.syscall.name") == "vfork" then
            log_vfork = log
            vfork_count = vfork_count + 1
        elseif event_type == "EXECVE" then
            log_execve = log
        end
    end

    if log_execve ~= "" and log_vfork ~= "" and vfork_count > 0 then
        local parent_pid = log_vfork:gets("initiator.process.parent.id") or ""
        local child_pid = log_vfork:gets("initiator.process.id") or ""
        local command = log_execve:gets("initiator.command.executed") or ""
        local process_path = log_vfork:gets("initiator.process.path.full") or ""
        local user_name = log_vfork:gets("initiator.user.name") or "unknown"
        local user_id = log_vfork:gets("initiator.user.id") or "unknown"

        alert({
            template = template,
            meta = {
                observer_ip = log_execve:gets("observer.host.ip") or "",
                observer_hostname = log_execve:gets("observer.host.hostname") or "",
                observer_fqdn = log_execve:gets("observer.host.fqdn") or "",
                user_name = user_name,
                user_id = user_id,
                process_path = process_path,
                command = command,
                parent_pid = parent_pid,
                child_pid = child_pid,
                suspicious_path = command,
                detection_count = tostring(vfork_count)
            },
            risk_level = 7.5,
            asset_ip = log_execve:get_asset_data("observer.host.ip"),
            asset_hostname = log_execve:get_asset_data("observer.host.hostname"),
            asset_fqdn = log_execve:get_asset_data("observer.host.fqdn"),
            asset_mac = "",
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "",
            logs = grouped.aggregatedData.loglines,
            mitre = {"T1036.004", "T1578.004", "T1564.007"},
            trim_logs = 10
        })
        grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)