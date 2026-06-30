local template = [[
Подозрение на маскировку процесса через SYSCALL vfork и SYSCALL clone.

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{ or .Meta.ip "IP-адрес не определён" }}
Хост: {{ or .Meta.hostname "Имя узла не определено" }}
FQDN: {{ or .Meta.observer_fqdn "FQDN узла не определено" }}

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
local prefix = "(?:^|\\/|\\s+|\"|\'|\\()"
local suffix = "(?:$|\\/|\\s+|\"|\'|\\))"
local suspicious_patterns = {   
                        prefix .. "while\\s+true;\\s*do\\s+[\\s\\S]*&\\s+\\w+\\s+\\$![\\s\\S]*ps[\\s\\S]*grep[\\s\\S]*awk[\\s\\S]*shuf[\\s\\S]*mount" .. suffix,
                        prefix .. "[-\\w\\/]+\\s+&\\s+(?:ps|pgrep|lsof|ss|systemctl|[hia]?top|fuser|uhide)" .. suffix,
                        prefix .. "sh\\s+-c\\s+(?:\\.\\w{6,}|\\w+\\s+[|&]|\\$\\{.*\\})" .. suffix,
                        prefix .. "(?:\\./\\w{8,}|\\$\\([\\s\\S]*?\\)|exec\\s+|>\\s*/dev/null)" .. suffix
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
            set_field_value(logline, "event.process.id", logline:gets("observer.event.id"))
            grouper2:feed(logline)
        end
    end
end

function on_grouped1(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_sys_execve, log_sys_masq
    

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local syscall_name = event:gets("target.syscall.name"):lower()

            if syscall_name == "execve" then
                log_sys_execve = event
            else
                log_sys_masq = event
            end
        end

        if log_sys_execve and log_sys_masq then
            local observer_pid = log_sys_execve:gets("observer.event.id")
            set_field_value(log_sys_execve, "event.process.id", observer_pid)
            set_field_value(log_sys_masq, "event.process.id", observer_pid)
            grouper2:feed(log_sys_execve)
            grouper2:feed(log_sys_masq)
            grouper1:clear()
        end

    end
end

function on_grouped2(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_execve, log_masq, log_syscall

    if unique_events > 1 then

        for _, event in ipairs(events) do
            local event_type = event:gets("observer.event.type")
                        
            if event_type == "SYSCALL" then
                local syscall_name = event:gets("target.syscall.name"):lower()
                
                if syscall_name == "vfork" or syscall_name == "clone" then
                    log_masq = event
                else
                    log_syscall = event
                end
            elseif event_type == "EXECVE" then
                log_execve = event
            end
        end

        if log_execve and log_masq and log_syscall then
            local command_executed = log_execve:gets("initiator.command.executed")
            local process_path = log_masq:gets("initiator.process.path.full")
            local initiator_name = log_masq:gets("initiator.user.name", "Имя пользователя не определено")
            local host_ip = log_execve:gets("observer.host.ip")
            local host_name = log_execve:gets("observer.host.hostname")
            local host_fqdn = log_execve:gets("observer.host.fqdn")
            local parent_pid = log_syscall:gets("initiator.process.parent.id")
            local target_pid = log_syscall:gets("initiator.process.id")
            
            if #command_executed > 255 then
                command_executed = command_executed:sub(1,255) .. "... "
            end

            alert({
                template = template,
                meta = {
                    ip = host_ip,
                    hostname = host_name,
                    user_name = initiator_name,
                    path = process_path,
                    command = command_executed,
                    parent_pid = parent_pid,
                    child_pid = target_pid
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