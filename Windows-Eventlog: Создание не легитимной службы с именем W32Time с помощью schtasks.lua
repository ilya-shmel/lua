-- Шаблон алерта
local template = [[
Обнаружено создание нелегитимной службы через schtasks.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ or .Meta.host_ip "IP-адрес узла не определён" }}
Имя узла: {{ or .Meta.hostname "Имя узла не определено" }}
Пользователь (инициатор): {{ or .Meta.user_name "Имя пользователя не определено" }}
Команда-инициатор: {{ .Meta.initiator_command }} 
Команда в задаче: {{ .Meta.target_command }}
Запускающая команда: {{ .Meta.program }}   
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "initiator.auth.logon.id"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения, шаблоны
local pattern = "\\.exe\\s+[-\\w]+(?:\\s+bypass)?(?:\\s+-[-\\w]+)?\\s+-file\\s+[^:]+:\\\\.+\\.(?:ps1|bat|cs|exe)"

-- Функция работы с логлайном
function on_logline(logline)
    local command_executed = logline:gets("initiator.command.executed")
    local is_task = command_executed:search(pattern)

    if is_task then grouper1:feed(logline) end
    
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec, log_task

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id= event:gets("observer.event.id")

            if compare(event_id, "==", "4698") then
                log_task = event
            else
                log_exec = event
            end 
        end
        
        if log_exec and log_task then
            local initiator_name = log_task:gets("initiator.user.name", "Пользователь не определён")  
            local host_ip = log_exec:get("observer.host.ip")
            local host_name = log_exec:gets("observer.host.hostname")
            local host_fqdn = log_exec:gets("observer.host.fqdn")
            local program_name = log_task:gets("target.image.name")
            local command_executed = log_exec:gets("initiator.command.executed")
            local command_scheduled = log_task:gets("initiator.command.executed")
            local process_path = log_exec:get("target.process.path.full")

            if #command_executed > 128 then
                command_executed = command_executed:sub(1, 128).. "... "
            end

            if #command_scheduled > 128 then
                command_scheduled = command_scheduled:sub(1, 128).. "... "
            end

            alert({
               template = template,
               meta = {
                   user_name=initiator_name,
                   initiator_command=command_executed,
                   target_command=command_scheduled,
                   path=process_path,
                   program=program_name,
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
               mitre = {"T1036.004"},
               trim_logs = 10
               }
            )
            grouper1:clear()
        end
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)