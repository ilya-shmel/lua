-- Шаблон алерта
local template = [[
Подозрение на запуск base64-закодированного скрипта PowerShell.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{ .Meta.command }}
Имя скрипта/модуля: {{ .Meta.file_name }}
Целевой файл/объект: {{ .Meta.object_name }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "event.process.id"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Функция работы с логлайном
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")

    if compare(event_id, "==", "4688") then
        local command_executed = logline:gets("initiator.command.executed"):lower()
        local is_base64 = command_executed:search("(?:^|\\s|\'|\"|\\/)powershell\\.exe\\s+-e(ncodedcommand)?\\s+([\\w,+,\\/,%,=]+)")
        
        if is_base64 then
            local process_id = logline:gets("target.process.id")
            set_field_value(logline, "event.process.id", process_id)
            grouper1:feed(logline)
        end
    elseif compare(event_id, "==", "4103") then
        local process_id = logline:gets("observer.process.id")
        set_field_value(logline, "event.process.id", process_id)
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec = nil
    local log_module = nil
    
    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")

            if compare(event_id, "==", "4688") then
                log_exec = event
            else    
                log_module = event
            end
        end
        
        if log_exec and log_module then 
            local initiator_name = log_module:gets("initiator.user.name", "Пользователь не определён")  
            local host_ip = log_exec:get("observer.host.ip") or log_exec:gets("reportchain.collector.host.ip", "IP-адрес не определён") 
            local host_name = log_exec:gets("observer.host.hostname")
            local host_fqdn = log_exec:gets("observer.host.fqdn")
            local command_executed = log_exec:gets("initiator.command.executed")
            local cmdlet = log_module:gets("initiator.process.command")
            local target_command = log_module:gets("target.object.name")

            if #command_executed > 128 then
                command_executed = command_executed:sub(1, 128).. "... "
            end


            if #target_command > 128 then
                target_command = target_command:sub(1, 128).. "... "
            end

            alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command=command_executed,
                    target_command=target_command,
                    cmdlet=cmdlet,
                    hostname=host_name,
                    host_ip=host_ip
                    },
                risk_level = 9.0, 
                asset_ip = host_ip,
                asset_hostname = host_name,
                asset_fqdn = host_fqdn,
                asset_mac = "",
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                logs = events,
                mitre = { "T1027.010", "T1059.001" },
                trim_logs = 10
                }
            )
            grouper1:clear()
        end
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)