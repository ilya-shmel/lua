-- Шаблон алерта
local template = [[
Подозрение на обнаружение неавторизованного DHCP-сервера.  

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Запрашиваемый IP-адрес: {{ .Meta.target_ip }}
MAC-адрес узла: {{ .Meta.mac }}
]]

-- Параметры группера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "initiator.interface.mac"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Функция работы с логлайном
function on_logline(logline)
    grouper1:feed(logline)
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local first_event = events[1]

    if #events > 0 then
        local host_ip = first_event:get("observer.host.ip") or first_event:gets("reportchain.collector.host.ip")
        local host_name = first_event:gets("observer.host.hostname", "Имя узла не определено")
        local host_fqdn = first_event:gets("observer.host.fqdn")
        local initiator_mac = first_event:gets("initiator.interface.mac", "MAC-адрес не определён")
        local initiator_ip = first_event:gets("initiator.host.ip", "IP-адрес не определён")

        if  host_ip == "" then 
            host_ip = "IP-адрес не определён"
        end
        
        alert({
            template = template,
            meta = {
                mac=initiator_mac,
                initiator_ip=initiator_ip,
                host_ip=host_ip,
                hostname=host_name
                },
            risk_level = 7.0, 
            asset_ip = first_event:gets("observer.host.ip"),
            asset_hostname = host_name,
            asset_fqdn = host_fqdn,
            asset_mac = "",
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "",
            logs = events,
            mitre = {"T1557"},
            trim_logs = 10
            }
        )
       
       grouper1:clear()
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)