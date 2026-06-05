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

-- Регулярные выражения, шаблоны

local function parseKeyValueSimple(string)
    local result = {}
    -- Убираем @{ и }
    local content = string:match("^@{(.*)}$")
    
    for pair in content:gmatch("([^;]+)") do
        local key, value = pair:match("^(%w+)%s*=%s*(.+)$")
        if key and value then
            -- Приводим типы
            if value == "True" then
                result[key] = true
            elseif value == "False" then
                result[key] = false
            elseif tonumber(value) then
                result[key] = tonumber(value)
            else
                result[key] = value
            end
        end
    end
    
    return result
end

-- Функция работы с логлайном
function on_logline(logline)
    local object_type = logline:gets("target.object.type"):lower()
    local object_data = {}

    if object_type == "object" then 
        local process_id = logline:gets("observer.process.id")
        set_field_value(logline, "event.process.id", process_id)
        grouper1:feed(logline)
    elseif object_type == "inputobject" then
        local object_name = logline:gets("target.object.name")
        object_data = parseKeyValueSimple(object_name)
        
        local test_guid = object_data.TestGuid
        local process_id = object_data.ProcessId
        local command_line = object_data.CommandLine
        local test_status = object_data.TestSuccess

        if test_guid and process_id then
            set_field_value(logline, "target.object.original", test_guid)
            set_field_value(logline, "event.process.id", process_id)
            set_field_value(logline, "initiator.process.command", command_line)
            set_field_value(logline, "target.object.status", test_status)
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
    
    log("Events: " ..#events.. ". Unique events: " ..unique_events)

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local object_type = logline:gets("target.object.type"):lower()

            if object_type == "object" then
               log_exec = event
            elseif event_type == "inputobject" then
                log_result = event
            end
        end

        local object_name = log_exec:gets("target.object.name")
        local object_original = log_result:gets("target.object.original")

        if compare (object_name, object_original, "==") then
            local initiator_name = log_exec:get("initiator.user.name") 
            local host_ip = log_exec:get("observer.host.ip") or log_exec:gets("reportchain.collector.host.ip", "IP-адрес не определён") 
            local host_name = log_exec:gets("observer.host.hostname", "Имя узла не определёно")
            local host_fqdn = log_exec:gets("observer.host.fqdn", "FQDN узла не определёно")
            local command_executed = log_exec:gets("initiator.command.executed")
            
            if compare(log_result:gets("target.object.status"):lower(), "true", "==") then
                status = "Команда выполнена успешно"
            end
            
            if #command_executed > 128 then
                command_executed = all_commands:sub(1, 128).. "... "
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