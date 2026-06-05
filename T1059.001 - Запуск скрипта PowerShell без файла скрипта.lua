-- Шаблон алерта
local template = [[
Подозрение на несанкционированное использование PowerShell в качестве интерпретатора вредоносных команд и скриптов.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена скрытая команда: {{ .Meta.command }}
Цепочка команд: {{ .Meta.all_commands }}
Начальный объект: {{ .Meta.source }}
Конечный объект: {{ .Meta.destination }}
]]

-- Параметры группера
local detection_window = "1m"
local grouped_by = { "observer.host.ip", "observer.host.hostname", "observer.process.id" }
local aggregated_by = {"event.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения, шаблоны
local process_commands = { 
    { action = "read", command = "get-itemproperty" },
    { action = "read", command = "get-content" }, 
    { action = "write", command ="set-content" },
    { action = "execute", command = "invoke-expression" }
}
--local registry_prefixes = { "HKCU:\\", "HKLM:\\", "HKCR:\\", "HKU:\\", "HKCC:\\" } 

-- Функция работы с логлайном
function on_logline(logline)
    local cmdlet = logline:gets("initiator.process.command"):lower()
    
    for _, pattern in pairs(process_commands) do
        if cmdlet:search(pattern.command) then
            set_field_value(logline, "event.type", pattern.action)
            grouper1:feed(logline)
        end
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec = nil
    local log_read = nil
    local log_write = nil
    local commands = {}
    local all_commands = nil
    
    log("Events: " ..#events.. ". Unique events: " ..unique_events)

    if unique_events > 2 then
        for _, event in ipairs(events) do
            local event_type = event:gets("event.type")
            local command_executed = event:gets("initiator.command.executed")
            table.insert(commands, command_executed)

            if event_type == "execute" then
               log_exec = event
            elseif event_type == "read" then
                log_read = event
            elseif event_type == "write" then
                log_write = event 
            end
        end

        local hash_table = {}
        local result_table = {}
        -- Поиск только утикальных значений в таблице команд
        for _, element in ipairs(commands) do
            if not hash_table[tostring(element)] then
                table.insert(result_table, tostring(element)) 
                hash_table[element] = true          
            end
        end

        commands = result_table
        all_commands = table.concat(commands, ", ")
    
        if log_exec and log_read and log_write  then
            local initiator_name = log_exec:get("initiator.user.name") 
            local host_ip = log_exec:get("observer.host.ip") or log_exec:gets("reportchain.collector.host.ip", "IP-адрес не определён") 
            local host_name = log_exec:gets("observer.host.hostname", "Имя узла не определёно")
            local host_fqdn = log_exec:gets("observer.host.fqdn", "FQDN узла не определёно")
            local hidden_command = log_exec:gets("target.object.name")
            local source_path = log_read:gets("target.object.name")
            local destination_path = log_write:get("target.object.name")

            if #all_commands > 128 then
                all_commands = all_commands:sub(1, 128).. "... "
            end

             alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command=hidden_command,
                    service=service_name,
                    hostname=host_name,
                    host_ip=host_ip,
                    all_commands=all_commands,
                    source=source_path,
                    destination=destination_path 
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