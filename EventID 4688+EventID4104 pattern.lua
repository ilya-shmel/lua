-- Шаблоны алерта
local template = [[
	<Title>

    Узел: 
    IP-адрес: {{ or .Meta.ip "IP-адрес не определён" }}
    Имя узла: {{ .Meta.hostname }}
    Пользователь (инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Исполняемый файл: {{ .Meta.path }}
]]

-- Переменные для группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "event.process.id"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Функция работы с логлайном
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")

    if compare(event_id, "==", "4104") then
        local process_id = logline:gets("observer.process.id")
        set_field_value(logline, "event.process.id", process_id)
        log("Log EXEC PID: " ..tostring(process_id))
    else 
        local process_id = logline:gets("initiator.process.parent.id")
        process_id = tonumber(process_id:gsub("^0[xX]", ""), 16)
        set_field_value(logline, "event.process.id", process_id)
        log("Log ScriptBlock PID: " ..tostring(process_id))
    end
    grouper1:feed(logline)
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_scriptblock = nil
    local log_exec = nil
    
    log("Events: " ..#events.. ". Unique events: " ..unique_events)

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")

            if compare(event_id, "==", "4688") then
                log_exec = event
            else 
                log_scriptblock = event
            end

        end

        if log_scriptblock and log_exec then
            local initiator_name = log_exec:get("initiator.user.name") or "Пользователь не определен" 
            local host_ip = log_scriptblock:get("observer.host.ip") or log_scriptblock:get("reportchain.collector.host.ip")
            local host_name = log_scriptblock:gets("observer.host.hostname", "Имя узла не опредено")
            local host_fqdn = log_scriptblock:gets("observer.host.fqdn")
            local command_executed = log_scriptblock:gets("initiator.command.executed")
            local target_image = log_exec:get("target.image.name") or log_exec:get("target.process.path.full") or "Имя файла не определено"
       
            if #command_executed > 128 then
                 command_executed = command_executed:sub(1,128).. "..."
            end

            alert({
                 template = template,
                 meta = {
                     user_name=initiator_name,
                     command=command_executed,
                     path=target_image,
                     ip=host_ip,
                     hostname=host_name
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
                 mitre = {"T1046", "T1205.001", "T1558.003", "T1558.004", "T1187", "T1082", "T1518"},
                 trim_logs = 10
                 }
            )
            grouper1:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)