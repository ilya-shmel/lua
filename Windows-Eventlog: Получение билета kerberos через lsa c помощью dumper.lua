-- Шаблон алерта
local template = [[
Обнаружена попытка сбора информации через LSA c помощью dumper..

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{ or .Meta.ip "IP-адрес не определён" }}
Узел: {{ or .Meta.hostname "Имя узла не определено" }}
FQDN: {{ or .Meta.fqdn "FQDN узла не определено" }}

ИНИЦИАТОР:
Пользователь: {{ or .Meta.user "Пользователь не определён"}}
Выполнено от имени: {{ or .Meta.executor "Пользователь не определён"}}

ВЫПОЛНЕННАЯ КОМАНДА:
{{ .Meta.command }}
Процесс/Путь к исполняемому файлу: {{ .Meta.path }}
Служба: {{ .Meta.service }}
Имя программы: {{ .Meta.program }}
Исходный объект: {{ .Meta.source_file }}
Результирующий объект: {{ .Meta.destination_file }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "observer.process.id"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local reg_pattern = [[(?:^|\/|\s+|"|'|\|)reg(?:\/|\s+|"|'|)\s+save\s+hk\w+(\\[^\\:]*)+\s+\w:(\\[^\\:]*)+]]
local iex_pattern = [[(?:^|\/|\s+|"|'|\|)(?:iex|invoke-expression)\s+\([^)]+\)\.[^(]+\(['"]?[\s\S]*\.ps(?:1|m)['"]?\)]]
local member_pattern = [[@\{((?:username|domain|logonid|usersid|authenticationpackage|logontype|logontime|logonserverdnsdomain)=[^;]*(;\s+)?)+\}]] 

local function log_grouper(events, events_number, unique_events, grouper_name, grouper_field)
    log("### " .. grouper_name .. " ###")
    log("Events: " ..#events.. ". Unique events: " ..unique_events)
    
    for _, event in ipairs(events) do
	    log("Event ID: " .. tostring(event:gets("observer.event.id")))
        log("Grouper field: " .. tostring(event:gets(grouper_field))) 
    end    
end

-- Функция сокразения строки для алерта
local function string_cut(cmd)
    if #cmd > 256 then
        cmd = cmd:sub(1, 256).. "... "
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
    local event_id = logline:gets("observer.event.id")

--    log("EventID: " .. tostring(event_id))

    if compare(event_id, "==", "4688") then
        local command_executed = logline:gets("initiator.command.executed"):lower()

        if command_executed == "c:\\windows\\psexesvc.exe" or command_executed:search(reg_pattern) then
            grouper1:feed(logline)
        end         
    elseif compare(event_id, "==", "4663") then
        grouper1:feed(logline)
    elseif compare(event_id, "==", "4104") then
        local command_executed = logline:gets("initiator.command.executed"):lower()
        
        if command_executed:search(iex_pattern) then
            grouper2:feed(logline)
        end
    elseif compare(event_id, "==", "4103") then
        local target_object = logline:gets("target.object.name"):lower()
        
        if target_object:search(member_pattern) then
            grouper2:feed(logline)
        end
    end
end

-- Функция группера #1
function on_grouped1(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec, log_service, log_file
    
--    log_grouper(events, #events, unique_events, "on_grouped", grouped_by[4])

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")
            if compare (event_id, "==", "4688") then
                local target_image = event:gets("target.image.name"):lower()

                if target_image == "psexesvc.exe" then
                    log_service = event
                else
                    log_exec = event
                end
            else
                log_file = event
            end
        end

        if log_exec and log_service and log_file then
            local initiator_name = log_exec:gets("initiator.user.name")  
            local executor_name = log_service:gets("initiator.user.name")
            local host_ip = log_exec:gets("observer.host.ip")
            local host_name = log_exec:gets("observer.host.hostname")
            local host_fqdn = log_exec:gets("observer.host.fqdn")
            local program_name = log_exec:gets("target.image.name")
            local service_name = log_service:gets("initiator.command.executed")
            local command_executed = string_cut(log_exec:gets("initiator.command.executed"))
            local process_path = log_exec:gets("target.process.path.full")
            local output_path = log_file:gets("target.object.name")
            local source_path = command_executed:match("save%s+([%s%S]*)%s+%a:")

            alert({
               template = template,
               meta = {
                   user=initiator_name,
                   executor=executor_name,
                   command=command_executed,
                   path=process_path,
                   program=program_name,
                   service=service_name,
                   source_file=source_path,
                   destination_file=output_path,
                   ip=host_ip,
                   hostname=host_name,
                   fqdn=host_fqdn
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
               mitre = {"T1003.004"},
               trim_logs = 10
               }
            )
            grouper1:clear()
        end

    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped1)
grouper2 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped2)