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
Идентификатор родительского процесса: {{.Meta.parent_pid}}
Идентификатор "дочернего" процесса: {{.Meta.child_pid}}

ВЫПОЛНЕННАЯ КОМАНДА:
{{.Meta.command}}
]]

local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

local suspicious_patterns = {   
                                "[\\s\'\"(]+while\\s+true;(\\s+do(ne)?[\\s;:)]+){2}&[\'\";\\s]+\\w+\\s+\\$!\\s+[>]+\\s+[\\/\\w\\.]+;[\\s\\S]*?[$(\\s]+ps[-\\s\\w]+\\|\\s+grep[$(\\s]+[\\\\,\'\"\\.\\*\\[\\]\\s]+\\|\\s+awk\\s+[\'\"{}$\\s\\w]+\\|\\s+shuf[-\\w\\s);]+mount[-\\w\\s]+([\\/\\w$()\\.\\s]+){1,2}",
                                "[-\\w\\/]+\\s+&\\s+(?:ps|lsof|ss|\\w+?top|pgrep|fuser|systemctl|uhide(-tcp))",
                                "(ba)?sh\\s+-c\\s+(?:\\./[a-zA-Z0-9]{6,}|[a-zA-Z0-9/]{1,}\\s+\\||\\$\\{.*\\})",
                                "\\./[a-zA-Z0-9]{8,}",
                                "\\$\\(.*\\)", "exec\\s+",
                                ">\\s*/dev/null"
}

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
    local event_type = logline:gets("observer.event.type")

    if event_type == "SYSCALL" then
        log("Sending Syscall to grouper!")
        grouper1:feed(logline)
    elseif event_type == "EXECVE" then
        log("Sending Esecve to grouper!")
        local cmd = logline:gets("initiator.command.executed")
        if analyze(cmd) then
            grouper1:feed(logline)
        end
    end
end

function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_execve = nil
    local log_vfork = nil
    local log_syscall = nil
    local vfork_count = 0
    local syscall_count = 0

    if unique_events > 1 then
        local type1 = events[1]:gets("observer.event.type")
        local type2 = events[2]:gets("observer.event.type")
        local syscall_name1 = events[1]:gets("target.syscall.name", "Not SYSCALL")
        local syscall_name2 = events[2]:gets("target.syscall.name", "Not SYSCALL")

        log("Events: " ..#events.. ". Unique events: " ..unique_events)
        log("Type 1: " ..type1.. ". Type 2: " ..type2)
        log("Syscall name1: " ..syscall_name1.. ". Syscall name2: " ..syscall_name2)
        
        for _, log in ipairs(events) do
            local event_type = log:gets("observer.event.type")
                        
            if event_type == "SYSCALL" then
                local syscall_name = log:gets("target.syscall.name")
                
                if syscall_name == "vfork" then
                    log_vfork = log
                    vfork_count = vfork_count + 1
                else
                    log_syscall = log
                    syscall_count = syscall_count + 1
                end
            elseif event_type == "EXECVE" then
                log_execve = log
            end
        end

        if log_execve and log_vfork and log_syscall and vfork_count > 0 and syscall_count > 0 then
            local initiator_id = log_vfork:gets("initiator.process.id")
            local target_pid = log_syscall:gets("initiator.process.id")
            local parent_pid = log_syscall:gets("initiator.process.parent.id")
            
            if initiator_id == target_pid then
                local command = log_execve:gets("initiator.command.executed")
                local process_path = log_vfork:gets("initiator.process.path.full")
                local user_name = log_vfork:gets("initiator.user.name") or "Имя пользователя не определено"
                local user_id = log_vfork:gets("initiator.user.id") or "Идентификатор пользователя не определен"

                   alert({
                    template = template,
                    meta = {
                        observer_ip = log_execve:gets("observer.host.ip"),
                        observer_hostname = log_execve:gets("observer.host.hostname"),
                        observer_fqdn = log_execve:gets("observer.host.fqdn"),
                        user_name = user_name,
                        user_id = user_id,
                        process_path = process_path,
                        command = command,
                        parent_pid = initiator_pid,
                        child_pid = parent_pid,
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
                    logs = events,
                    mitre = {"T1036.004", "T1578.004", "T1564.007"},
                    trim_logs = 10
                })
                grouper1:clear()
            end
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)