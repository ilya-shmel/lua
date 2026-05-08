local_networks = storage.new("local_networks|Использование протокола без шифрования2")

-- Шаблон алерта
local template = [[
Зафиксировано использование протокола без шифрования. 

УЗЕЛ-ИНИЦИАТОР:
IP-адрес: {{ .Meta.initiator_ip }}
Имя узла: {{ .Meta.hostname }}

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.target_ip }}
Целевой порт {{ .Meta.port }}
Протокол: {{ .Meta.protocol }}   
]]

-- Параметры группера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "event.application.protocol"}
local aggregated_by = {"target.socket.port"}
local grouped_time_field = "@timestamp,RFC3339"

local http_ports = {"80","8080"}
local vnc_ports = {"5900", "5901", "5902", "5903", "5904"}
local socket_ports = {
    ["FTP"] = "21",
    ["Telnet"] = "23",
    ["MSSQL"] = "1433",
    ["Oracle"] = "1521",
    ["MySQL"] = "3306",
    ["Memcached"] = "11211",
    ["RabbitMQ"] = "15672",
    ["MongoDB"] = "27017"
}
local masks = {"24", "16", "12"}

-- Функция работы с логлайном
function on_logline(logline)
    local initiator_ip = logline:gets("initiator.host.ip")
    local target_ip = logline:gets("target.host.ip")
    local target_port = logline:gets("target.socket.port")
    local is_local_initiator = nil
    local is_local_target = nil
    local tartet_protocol = ""

    is_local_initiator = local_networks:get(tostring(initiator_ip), "cidr")
    is_local_target = local_networks:get(tostring(target_ip), "cidr")

    if is_local_initiator then 
        if is_local_target and compare(target_port, "==", "80") or (not is_local_target and contains(socket_ports, "exact", tostring(target_port))) then
            grouper1:feed(logline)
        elseif contains(vnc_ports, tostring(target_port)) then
            grouper1:feed(logline)
        else 
            for protocol, port in ipairs(socket_ports) do 
                if compare(target_port, "exact", port) then
                    grouper1:feed(logline)
                end
            end
        end
    end
    

end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local first_event = events[1]

    if #events > 0 then
        local host_ip = first_event:get("observer.host.ip") or first_event:get("reportchain.collector.host.ip")
        local host_name = first_event:gets("observer.host.hostname", "Имя узла не определено")
        local host_fqdn = first_event:gets("observer.host.fqdn")
        local initiator_ip = first_event:gets("initiator.host.ip")
        local target_host_ip = first_event:gets("target.host.ip")
        local target_socket_port = first_event:gets("target.socket.port")
        local target_protocol = first_event:gets("event.application.protocol")

         alert({
            template = template,
            meta = {
                initiator_ip=initiator_ip,
                hostname=host_name,
                target_ip=target_host_ip,
                port=target_socket_port,
                protocol=target_protocol
                },
            risk_level = 4.0, 
            asset_ip = host_ip,
            asset_hostname = host_name,
            asset_fqdn = host_fqdn,
            asset_mac = "",
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "",
            logs = events,
            mitre = {"T1557", "T1557.003", "T1048", "T1048.003"},
            trim_logs = 10
            }
        )
       grouper1:clear()
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)