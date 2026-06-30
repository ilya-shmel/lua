local template = [[
    Обнаружена сетевая разведка.
    Узел: 
    IP - {{ or .Meta.ip "IP-адрес не определён" }}
    Hostname - {{ or .Meta.hostname "Имя узла не определено" }}
    Пользователь(инициатор): {{ or .Meta.user_name "Имя пользователя не определно" }}
    Выполненная команда: {{ .Meta.command }}
    Путь выполнения команды: {{ .Meta.path }}
    Имя программы: {{ .Meta.program }}
    Целевой узел: {{ .Meta.target_host }}
    Целевой порт: {{ .Meta.port }}
]]

local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

local pattern = "(?:^|\\/|\\s+|\"|\'|\\()(?:arp|map|scan|netdiscover|nikto|dirb|ip|n(et)?c(at)?|ping|traceroute|netstat|ss|knock)\\s+(?:\\/|\\s+|\"|\'|\\))?"

function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    
    if event_type == "EXECVE" or event_type == "PROCTITLE" then
        local command_executed = logline:gets("initiator.command.executed")

        if command_executed:search(pattern) then
            grouper1:feed(logline)
        end
    else
        grouper1:feed(logline)
    end

end

function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_sys, log_sockaddr, log_exec

    if unique_events > 2 then
        for _, event in ipairs(events) do
            local event_type = event:gets("observer.event.type")
            if event_type == "SYSCALL" then
                log_sys = event
            elseif event_type == "EXECVE" or event_type == "PROCTITLE" then
                log_exec = event
            else 
                log_sockaddr = event
            end
        end

        if log_sys and log_sockaddr and log_exec then
            local command_executed = log_exec:gets("initiator.command.executed")
            local initiator_name = log_sys:gets("initiator.user.name")  
            local host_ip = log_sys:gets("observer.host.ip")
            local host_name = log_sys:gets("observer.host.hostname")
            local host_fqdn = log_sys:gets("observer.host.fqdn")
            local target_host = log_sockaddr:gets("initiator.host.ip")
            local target_port = log_sockaddr:gets("initiator.socket.port")
            local command_path = log_sys:gets("initiator.process.path.full")
            local program_name = command_path:match("[^/\\s]+$")

            alert({
                template = template,
                meta = {
                    user_name = initiator_name,
                    command = command_executed,
                    path = command_path,
                    hostname=host_name,
                    ip=host_ip,
                    program=program_name,
                    target_host=target_host,
                    port=target_port    
                },
                risk_level = 9.0,
                asset_ip = host_ip,
                asset_hostname = host_name,
                asset_fqdn = host_fqdn,
                asset_mac = "",
                create_incident = true,
                incident_group = "Discovery",
                assign_to_customer = false,
                logs = events,
                mitre = {"T1046"},
                trim_logs = 10
            })
            
            grouper1:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)