-- Шаблон алерта
local template = [[
Подозрение на запуск инструмента Mimikatz.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{ .Meta.command }}
Путь выполнения: {{ .Meta.script_name }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"target.image.name"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения, шаблоны

-- Функция работы с логлайном
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")

    if compare(event_id, "==", "4688") then
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total

    if #events > 0 then
        local first_event = events[1]
        
        local command_executed = first_event:gets("initiator.command.executed")
        local initiator_name = first_event:gets("initiator.user.name", "Пользователь не определён")
        local host_ip = first_event:get("observer.host.ip") or first_event:gets("reportchain.collector.host.ip", "IP-адрес не определён")
        local host_name = first_event:gets("observer.host.hostname", "Имя узла не определено")
        local host_fqdn = first_event:gets("observer.host.fqdn", "FQDN узла не определено")
        local parent_path = first_event:gets("initiator.process.parent.path.original")
        
        if command_executed > 128 then
            command_executed = command_executed:sub(1, 128).. "... "
        end
            
        alert({
           template = template,
           meta = {
                user_name=initiator_name,
                command=command_executed,
                parent=parent_path,
                file_name=file_path,
                hostname=host_name,
                ip=host_ip
                },
           risk_level = 6.5, 
           asset_ip = host_ip,
           asset_hostname = host_name,
           asset_fqdn = host_fqdn,
           asset_mac = "",
           create_incident = true,
           incident_group = "",
           assign_to_customer = false,
           incident_identifier = "",
           logs = events,
           mitre = {"T1059.001"},
           trim_logs = 10
           }
        )
       
        grouper1:clear()
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)