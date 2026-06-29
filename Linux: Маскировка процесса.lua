local template = [[
Подозрение на маскировку процесса через SYSCALL vfork.

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{ or .Meta.ip "IP-адрес не определён" }}
Хост: {{ or .Meta.hostname "Имя узла не определено" }}
FQDN: {{.Meta.observer_fqdn}}

ИНИЦИАТОР:
Пользователь: {{.Meta.user_name}}
Процесс: {{.Meta.path}}
Идентификатор родительского процесса: {{.Meta.parent_pid}}
Идентификатор "дочернего" процесса: {{.Meta.child_pid}}

ВЫПОЛНЕННАЯ КОМАНДА:
{{.Meta.command}}
]]

local detection_window1 = "30s"
local grouped_by1 = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "initiator.process.id", "initiator.process.parent.id"}
local aggregated_by1 = {"target.syscall.name"}

local detection_window2 = "30s"
local grouped_by2 = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "event.process.id"}
local aggregated_by2 = {"observer.event.type"}


local grouped_time_field = "@timestamp,RFC3339"

local suspicious_patterns = {   
                                "[\\s\'\"(]+while\\s+true;(\\s+do(ne)?[\\s;:)]+){2}&[\'\";\\s]+\\w+\\s+\\$!\\s+[>]+\\s+[\\/\\w\\.]+;[\\s\\S]*?[$(\\s]+ps[-\\s\\w]+\\|\\s+grep[$(\\s]+[\\\\,\'\"\\.\\*\\[\\]\\s]+\\|\\s+awk\\s+[\'\"{}$\\s\\w]+\\|\\s+shuf[-\\w\\s);]+mount[-\\w\\s]+([\\/\\w$()\\.\\s]+){1,2}",
                                "[-\\w\\/]+\\s+&\\s+(?:ps|lsof|ss|\\w+?top|pgrep|fuser|systemctl|uhide(-tcp))",
                                "(ba)?sh\\s+-c\\s+(?:\\./[a-zA-Z0-9]{6,}|[a-zA-Z0-9/]{1,}\\s+\\||\\$\\{.*\\})",
                                "\\./[a-zA-Z0-9]{8,}",
                                "\\$\\([\\s\\S]*?\\)",
                                "exec\\s+",
                                ">\\s*/dev/null"
}

local function analyze(cmd)
    local cmd_lower = cmd:lower()
    for _, pattern in ipairs(suspicious_patterns) do
        if cmd_lower:search(pattern) then
            return true
        end
    end
    return false
end

function on_logline(logline)
    local event_type = logline:gets("observer.event.type")

    if event_type == "SYSCALL" then
        grouper1:feed(logline)
    elseif event_type == "EXECVE" then
        local cmd = logline:gets("initiator.command.executed")
        if analyze(cmd) then
            set_field_value(logline, "event.process.id", logline:gets("observer.process.id"))
            grouper2:feed(logline)
        end
    end
end

function on_grouped1(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_sys_execve, log_sys_vfork
    
    log("Events: " ..#events.. ". Unique events: " ..unique_events)

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local syscall_name = event:gets("target.syscall.name"):lower()
                
            if syscall_name == "execve" then
                log_sys_execve = event
            else
                log_sys_vfork = event
            end
        end

        if log_sys_execve and log_sys_vfork then
            local observer_pid = log_sys_execve:gets("observer.event.id")
            set_field_value(log_sys_execve, "event.process.id", observer_pid)
            set_field_value(log_sys_vfork, "event.process.id", observer_pid)
            grouper2:feed(log_sys_execve)
            grouper2:feed(log_sys_vfork)
            grouper1:clear()
        end

    end
end

function on_grouped2(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_execve, log_vfork, log_syscall

    if unique_events > 1 then

        for _, event in ipairs(events) do
            local event_type = log:gets("observer.event.type")
                        
            if event_type == "SYSCALL" then
                local syscall_name = log:gets("target.syscall.name"):lower()
                
                if syscall_name == "vfork" then
                    log_vfork = event
                else
                    log_syscall = event
                end
            elseif event_type == "EXECVE" then
                log_execve = event
            end
        end

        if log_execve and log_vfork and log_syscall then
            local command_executed = log_execve:gets("initiator.command.executed")
            local process_path = log_vfork:gets("initiator.process.path.full")
            local initiator_name = log_vfork:gets("initiator.user.name", "Имя пользователя не определено")
            local host_ip = log_execve:gets("observer.host.ip")
            local host_name = log_execve:gets("observer.host.hostname")
            local host_fqdn = log_execve:gets("observer.host.fqdn")
            local parent_id = log_syscall:gets("")
                        
            alert({
                template = template,
                meta = {
                    ip = host_ip,
                    hostname = host_name,
                    user_name = initiator_name,
                    path = process_path,
                    command = command_executed,
                    parent_pid = initiator_pid,
                    child_pid = parent_pid
                },
                risk_level = 7.5,
                asset_ip = host_ip,
                asset_hostname = host_name,
                asset_fqdn = host_fqdn,
                asset_mac = "",
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                logs = events,
                mitre = {"T1036.004", "T1578.004", "T1564.007"},
                trim_logs = 10
            })
            grouper2:clear()
            
        end
    end
end

grouper1 = grouper.new(grouped_by1, aggregated_by1, grouped_time_field, detection_window1, on_grouped1)
grouper2 = grouper.new(grouped_by2, aggregated_by2, grouped_time_field, detection_window2, on_grouped2)