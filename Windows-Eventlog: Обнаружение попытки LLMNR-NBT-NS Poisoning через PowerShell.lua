-- Шаблон алерта
local template = [[
Обнаружена попытка использования LLMNR/NBT-NS Poisoning через PowerShell.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{ .Meta.command }}
Процесс: {{ .Meta.process }}   
Имя службы: {{ .Meta.service }}
]]

-- Параметры группера
local detection_window = "5m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "common.process.id"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

local function send_to_grouper(event, id)
    set_field_value(event, "common.process.id", id)
    grouper1:feed(event)
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")
    
    if event_id == 4104 then
       send_to_grouper(logline, logline:gets("observer.process.id"))
    elseif event_id == 5156 then
        local application_protocol = logline:gets("event.application.protocol")
        local event_direction = logline:gets("event.rule.direction")
        local target_port = logline:gets("target.socket.port")
        
        if compare(application_protocol, "==", "0") and event_direction == "%%14592" and compare(target_port, ">=", "49152") then
            send_to_grouper(logline, logline:gets("initiator.process.id"))
        end
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local posh_event = nil
    local filtering_event = nil

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")

            if event_id == 4104 then
                posh_event = event
            else
                filtering_event = event
            end
                
        end
    
        local initiator_name = filtering_event:gets("initiator.user.name", "Пользователь не определён")  
        local host_ip = filtering_event:get("observer.host.ip") or filtering_event:get("reportchain.collector.host.ip")
        local host_name = filtering_event:gets("observer.host.hostname", "Имя узла не определено")
        local host_fqdn = filtering_event:gets("observer.host.fqdn")
        local service_name = posh_event:gets("target.service.name", "Служба не определена")
        local command_executed = posh_event:gets("initiator.command.executed")
        local process_path = posh_event:get("initiator.process.path.full") or posh_event:get("initiator.process.path.name") or posh_event:gets("event.logsource.application", "Путь неопределён")

        if #command_executed > 128 then
            command_executed = command_executed:sub(1, 128).. "... "
        end

        alert({
            template = template,
            meta = {
                user_name=initiator_name,
                command=command_executed,
                process=process_path,
                service=service_name,
                host_ip=host_ip,
                hostname=host_name
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
            mitre = {"T1557"},
            trim_logs = 10
            }
        )
       grouper1:clear()
    end    
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)