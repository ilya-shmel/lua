-- Шаблон алерта
local template = [[
Подозрение на использование потенциально вредоносных командлетов PowerShell.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{.Meta.command}}
Имя файла: {{ .Meta.file_name}}
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
        local process_id = logline:gets("initiator.process.parent.id")
        set_field_value(logline, "event.process.id", process_id)
    elseif compare(event_id, "==", "4663") then
        local process_id = logline:gets("initiator.process.id")
        set_field_value(logline, "event.process.id", process_id)
    end

    grouper1:feed(logline)

end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec = nil
    local log_access = nil
    
    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")

            if compare(event_id, "==", "4688") then
                log_exec = event
            else    
                log_access = event
            end
        end
        
        if log_exec and log_access then 
            local initiator_name = log_exec:gets("initiator.user.name", "Пользователь не определён")  
            local host_ip = log_exec:get("observer.host.ip") or log_scriptblock_command:gets("reportchain.collector.host.ip", "IP-адрес не определён") 
            local host_name = log_exec:gets("observer.host.hostname")
            local host_fqdn = log_exec:gets("observer.host.fqdn")
            local command_executed = log_exec:gets("initiator.command.executed")
            local file_name = command_executed:match("([^/]+%.sct)[\'\"%)]") or "Имя файла не определено"

            if #command_executed > 128 then
                command_executed = command_executed:sub(1, 128).. "... "
            end

            alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command=command_executed,
                    file_name=file_name,
                    hostname=host_name,
                    host_ip=host_ip
                    },
                risk_level = 8.0, 
                asset_ip = host_ip,
                asset_hostname = host_name,
                asset_fqdn = host_fqdn,
                asset_mac = "",
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                logs = events,
                mitre = {"T1059.001", "T1218.005"},
                trim_logs = 10
                }
            )
            grouper1:clear()
        end
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)