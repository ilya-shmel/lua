-- Шаблон алерта
local template = [[
Обнаружены попытки доступа к сессиям RDP через дамп svchost.

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
Целевой файл: {{ .Meta.file }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "target.object.name"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local dump_pattern = [[(?:^|[\\\s"'(])rundll32(?:\.exe)?[\\\s"'\)]?\s+[\s\S]*?comsvcs(\.dll)?\s+[\s\S]*?minidump\s+\d+\s+\w:\\([^\\]*\\?)+\s+\w+]]
local dump_file_pattern = "%d+%s+\"?(%a:\\[^\"]+%.%w+)\"?%s+"

-- Вспомогательная функция логирования значений в группере (удалить после тестирования на потоке)
local function log_grouper(events, events_number, unique_events, grouper_name, grouper_field)
    log("### " .. grouper_name .. " ###")
    log("Events: " ..#events.. ". Unique events: " ..unique_events)
    
    for _, event in ipairs(events) do
	    log("Event ID: " .. tostring(event:gets("observer.event.id")))
        log("Grouper field: " .. tostring(event:gets(grouper_field))) 
    end    
end

-- Вспомогательная функция логирования значений в функции on_logline
local function log_on_logline(event)
    local event_id = tostring(event:gets("observer.event.id"))
    log("###  on_logline  ###")
    log("Event ID: " .. event_id)
    
    if compare(event_id, "==", "4688") then
        local command_executed = event:gets("initiator.command.executed") 
        local file_name = command_executed:match(dump_file_pattern)
        log("Command: " .. command_executed:lower())
        log("Pattern: " .. dump_pattern)
        log("Dump file pattern: " .. dump_file_pattern)
        log("Command regex result: " .. tostring(command_executed:lower():search(dump_pattern)))
        log("Dump file: " .. (file_name or "nil"))
    else
        log("Dump file: " .. event:gets("target.object.name"))
    end
end

-- Функция алерта
local function alert_function(events, ip, hostname, fqdn, user, cmd, program, path, file)
    alert({
        template = template,
        meta = {
            user=user,
            command=cmd,
            path=path,
            program=program,
            file=file,
            ip=ip,
            hostname=hostname,
            fqdn=fqdn
            },
        risk_level = 9.0, 
        asset_ip = ip,
        asset_hostname = hostname,
        asset_fqdn = fqdn,
        asset_mac = "",
        create_incident = true,
        incident_group = "",
        assign_to_customer = false,
        incident_identifier = "",
        logs = events,
        mitre = {"T1003"},
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

-- Функция обработки логлайна
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")
    log("EventID: " .. tostring(event_id))

    if compare(event_id, "==", "4688") then
        local command_executed = logline:gets("initiator.command.executed")
        local cmd_lower = command_executed:lower()
        log_on_logline(logline)

        if cmd_lower:search(dump_pattern) then
            dump_name = command_executed:match(dump_file_pattern)
            
            if dump_name then
                set_field_value(logline, "target.object.name", dump_name)
                grouper1:feed(logline)
            end
        end        
    else
        grouper1:feed(logline)
    end
end

-- Функция группера #1
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec, log_file
    
    log_grouper(events, #events, unique_events, "on_grouped", grouped_by[4])

    if unique_events > 1 then
        for _, event in ipairs(events) do
            if compare(event:gets("observer.event.id"), "==", 4688) then
                log_exec = event
            else
                log_file = event
            end
        end

        if log_exec and log_file and compare(log_exec:gets("target.process.id"), "==", log_file:gets("initiator.process.id")) then
            local initiator_name = log_exec:gets("initiator.user.name")  
            local host_ip = log_exec:gets("observer.host.ip")
            local host_name = log_exec:gets("observer.host.hostname")
            local host_fqdn = log_exec:gets("observer.host.fqdn")
            local program_name = log_exec:gets("target.image.name")
            local command_executed = string_cut(log_exec:gets("initiator.command.executed"))
            local process_path = log_exec:get("target.process.path.full")
            local dump_name = log_file:gets("target.object.name")

            alert_function(events, host_ip, host_name, host_fqdn, initiator_name, command_executed, program_name, process_path, dump_name)
            grouper1:clear()
        end

    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)