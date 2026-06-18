-- Шаблон алерта
local template = [[
Подозрение на переопределение системных команд.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{ .Meta.command }}
Набор связанных команд: {{ .Meta.next_commands }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = { "observer.host.ip", "observer.host.hostname", "observer.process.id" }
local aggregated_by = { "target.object.type" }
local grouped_time_field = "@timestamp,RFC3339"

-- Функция работы с логлайном
function on_logline(logline)
    grouper1:feed(logline)
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_invoke = nil
    local log_commands = {}
    
    --log("Events: " ..#events.. ". Unique events: " ..unique_events)

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local process_command = event:gets("initiator.process.command"):lower()

            if process_command:find("invoke-") then
                log_invoke = event
            else    
                local cmdlet = event:gets("initiator.process.command")
                local object_name = event:gets("target.object.name")
                table.insert(log_commands, cmdlet .. " " .. object_name)
            end
        end
             
        if log_invoke and #log_commands > 0 then 
            local initiator_name = log_invoke:gets("initiator.user.name", "Пользователь не определён")  
            local host_ip = log_invoke:get("observer.host.ip") or log_invoke:gets("reportchain.collector.host.ip", "IP-адрес не определён") 
            local host_name = log_invoke:gets("observer.host.hostname")
            local host_fqdn = log_invoke:gets("observer.host.fqdn")
            local command_executed = log_invoke:gets("initiator.process.command") .. " " .. log_invoke:gets("target.object.name") 
            local all_commands = table.concat(log_commands, "; ")

            if #command_executed > 128 then
                command_executed = command_executed:sub(1, 128).. "... "
            end

             if #all_commands > 128 then
                all_commands = all_commands:sub(1, 128).. "... "
            end

            alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command=command_executed,
                    next_commands=all_commands,
                    hostname=host_name,
                    host_ip=host_ip
                    },
                risk_level = 6.0, 
                asset_ip = host_ip,
                asset_hostname = host_name,
                asset_fqdn = host_fqdn,
                asset_mac = "",
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                logs = events,
                mitre = { "T1059.001" },
                trim_logs = 10
                }
            )
            grouper1:clear()
        end
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)