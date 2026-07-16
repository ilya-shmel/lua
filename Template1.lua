-- Шаблон алерта
local template = [[
Подозрение на маскировку процесса через SYSCALL vfork и SYSCALL clone.

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{ or .Meta.ip "IP-адрес не определён" }}
Узел: {{ or .Meta.hostname "Имя узла не определено" }}
FQDN: {{ or .Meta.fqdn "FQDN узла не определено" }}

ИНИЦИАТОР:
Пользователь: {{ or .Meta.user "Пользователь не определён"}}

ВЫПОЛНЕННАЯ КОМАНДА:
{{ .Meta.command }}
Имя программы: {{ .Meta.program }}
Процесс/Путь к иcполняемому файлу: {{ .Meta.path }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}
local aggregated_by = {"target.syscall.name"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local prefix = "(?:^|\\/|\\s+|\"|\'|\\()"
local suffix = "(?:$|\\/|\\s+|\"|\'|\\))"
local suspicious_patterns = {   
                        
}

-- Вспомогательная функция логирования значений в группере (удалить после тестирования на потоке)
local function log_grouper(events, events_number, unique_events, grouper_name, grouper_field)
    log("### " .. grouper_name .. " ###")
    log("Events: " ..#events.. ". Unique events: " ..unique_events)
    
    for _, event in ipairs(events) do
	    log("Event ID: " .. tostring(event:gets("observer.event.id")))
        log("Grouper field: " .. tostring(event:gets(grouper_field))) 
    end    
end

-- Функция алерта
local function alert_function(events, ip, hostname, fqdn, user, cmd, program, service, path, source, destination)
    alert({
        template = template,
        meta = {
            user=user,
            command=cmd,
            path=path,
            program=program,
            service=service,
            source_file=source,
            destination_file=destination,
            ip=ip,
            hostname=hostname,
            fqdn=fqdn
            },
        risk_level = 4.0, 
        asset_ip = ip,
        asset_hostname = hostname,
        asset_fqdn = fqdn,
        asset_mac = "",
        create_incident = true,
        incident_group = "",
        assign_to_customer = false,
        incident_identifier = "",
        logs = events,
        mitre = {"T1003.004"},
        trim_logs = 10
        }
     )
end

-- Функция сокращения строки для алерта
local function string_cut(cmd)
    if #cmd > 128 then
        cmd = cmd:sub(1, 128).. "... "
    end

    return cmd
end

-- Функция анализа строки по регулярному выражению
local function analyze(cmd)
    local cmd_lower = cmd:lower()
    for _, pattern in ipairs(suspicious_patterns) do
        if cmd_lower:search(pattern) then
            return true
        end
    end
    return false
end

-- Функция обработки логлайна
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    local event_id = logline:gets("observer.event.id")
    ...
    grouper1:feed(logline)
end

-- Функция группера #1
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_1, log_2
    
--    log_grouper(events, #events, unique_events, "on_grouped", grouped_by[4])

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local parameter = event:gets("..."):lower()

            if syscall_name == "" then
                log_1 = event
            else
                log_2 = event
            end
        end

        if log_1 and log_2 then
            local initiator_name = log_1:gets("initiator.user.name")  
            local host_ip = log_2:get("observer.host.ip")
            local host_name = log_2:gets("observer.host.hostname")
            local host_fqdn = log_2:gets("observer.host.fqdn")
            local program_name = log_1:gets("target.image.name")
            local command_executed = string_cut(log_2:gets("initiator.command.executed"))
            local process_path = log_2:get("target.process.path.full")

            alert_function(events, host_ip, host_name, host_fqdn, initiator_name, command_executed, program_name, service_name, process_path, source_path, output_path)
            grouper1:clear()
        end

    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)

---------------------------------------------------------------------------------------------------

-- Функция обработки логлайна для двух событий EventID 4104 и 4103
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")

    if compare(event_id, "==", "4104") then
        local command_executed = logline:gets("initiator.command.executed")
        
        if command_executed:search(suspicious_pattern) then
            grouper1:feed(logline)
        end
    else
        grouper1:feed(logline)
    end
end


-- Разбор событий в группере для двух событий EventID 4104 и 4103
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")

            if compare(event_id, "==", "4104") then
                log_scriptblock = event
            else
                log_module = event
            end
        end

------------------------------------------------------------------------------------------------------

-- Вспомогательная функция логирования значений в группере (удалить после тестирования на потоке)
local function log_grouper(events, events_number, unique_events, grouper_name, grouper_field)
    log("### " .. grouper_name .. " ###")
    log("Events: " ..#events.. ". Unique events: " ..unique_events)
    
    for _, event in ipairs(events) do
	    log("Event ID: " .. tostring(event:gets("observer.event.id")))
        log("Grouper field: " .. tostring(event:gets(grouper_field)) .. " ; " .. tostring(event:gets("event.rule.description")))
        log("Command executed: " .. event:gets("initiator.command.executed")) 
    end    
end