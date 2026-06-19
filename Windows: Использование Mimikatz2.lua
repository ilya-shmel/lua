-- Шаблон алерта
local template = [[
Обнаружена попытка дампа данных с использованием утилит SOAPHound, BloodHound или SharpHound.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{ .Meta.command }}
Выполненный скрипт/файл : {{ .Meta.script_name }}
Результирующий файл: {{ .Meta.file_name }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "event.process.id"}
local aggregated_by = {"target.image.name"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения, шаблоны

-- Функция работы с логлайном
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")

    if compare(event_id, "==", "4688") then
        local image_name = logline:gets("target.image.name"):lower()
        
        if  image_name:find("mimikatz.exe") then
            local process_id = logline:gets("initiator.process.parent.id")
            set_field_value(logline, "event.process.id", process_id)
            set_field_value(logline, "process.type", "child")
        else 
            local process_id = logline:gets("target.process.id")
            set_field_value(logline, "event.process.id", process_id)
            set_field_value(logline, "process.type", "parent")
        end
        
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_parent = nil
    local log_child = nil

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local process_type = event:gets("process.type")

            if process_type == "parent" then
                log_parent = event
            else
               log_child = event  
            end
        end

        if log_parent and log_child then 
            local command_executed = log_child:gets("initiator.command.executed")
            local initiator_name = log_parent:get("initiator.user.name") or log_child:gets("initiator.user.name", "Пользователь не определён")
            local host_ip = log_parent:get("observer.host.ip") or log_child:get("observer.host.ip") or log_parent:gets("reportchain.collector.host.ip", "IP-адрес не определён")
            local host_name = log_parent:get("observer.host.hostname") or log_child:gets("observer.host.hostname", "Имя узла не определено")
            local host_fqdn = log_parent:get("observer.host.fqdn") or log_child:gets("observer.host.fqdn", "FQDN узла не определено")
            local parent_path = log_parent:gets("initiator.process.parent.path.original")
            local target_path = log_child:gets("initiator.process.parent.path.original")

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
                    target=target_path,
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
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)