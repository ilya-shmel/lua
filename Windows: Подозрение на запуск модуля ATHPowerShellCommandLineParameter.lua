-- Шаблон алерта
local template = [[
Подозрение на запуск инструмента тестирования ATHPowerShellCommandLineParameter.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}

КОМАНДА:
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{ .Meta.command }}
ID выполненной команды: {{ .Meta.test_id }}
Результат команды: {{ .Meta.status }}
]]

-- Параметры группера
local detection_window = "1m"
local grouped_by = { "observer.host.ip", "observer.host.hostname", "event.process.id" }
local aggregated_by = {"target.object.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Функция работы с логлайном
function on_logline(logline)
    local object_type = logline:gets("target.object.type"):lower()
    local object_data = {}

    if object_type == "object" then 
        local process_id = logline:gets("observer.process.id")
        set_field_value(logline, "event.process.id", process_id)
        grouper1:feed(logline)
    elseif object_type == "inputobject" then
        local object_original = logline:gets("target.object.original")
        local event_id = logline:gets("event.process.id")    

        if object_original and event_id then
            grouper1:feed(logline)
        end
    end
    
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec = nil
    local log_result = nil
    local status = nil

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local object_type = event:gets("target.object.type"):lower()

            if object_type == "object" then
               log_exec = event
            else
               log_result = event
            end
        end

        local object_name = log_exec:gets("target.object.name")
        local object_original = log_result:gets("target.object.original")

        if compare (object_name, "==", object_original) and log_exec and log_result then
            local initiator_name = log_exec:get("initiator.user.name") 
            local host_ip = log_exec:get("observer.host.ip") or log_exec:gets("reportchain.collector.host.ip", "IP-адрес не определён") 
            local host_name = log_exec:gets("observer.host.hostname", "Имя узла не определёно")
            local host_fqdn = log_exec:gets("observer.host.fqdn", "FQDN узла не определёно")
            local command_executed = log_exec:gets("initiator.command.executed")
            
            if compare(log_result:gets("target.object.status"):lower(), "==", "true") then
                status = "Команда выполнена успешно"
            else
                status = "Команда завершилась с ошибкой"
            end
            
            if #command_executed > 128 then
                command_executed = command_executed:sub(1, 128).. "... "
            end

             alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command=command_executed,
                    hostname=host_name,
                    host_ip=host_ip,
                    test_id=object_name,
                    status=status 
                    },
                risk_level = 7.0, 
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