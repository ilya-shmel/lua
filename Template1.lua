-- Шаблон алерта
local template = [[
{{ .Meta.title }}.

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
Родительский процесс: {{ .Meta.parent }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by1 = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "event.auth.logon.id"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Шаблоны и паттерны
pattern1 = [[ ]]

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
local function alert_function(events, meta)
    alert({
        template = template,
        meta = meta,
        risk_level = meta.risk,
        asset_ip = meta.ip,
        asset_hostname = meta.hostname,
        asset_fqdn = meta.fqdn,
        asset_mac = "",
        create_incident = true,
        incident_group = "",
        assign_to_customer = false,
        incident_identifier = "",
        logs = events,
        mitre = meta.risk,
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

-- Функция обработки логлайна для одного события 4688
function on_logline(logline)
    local command_executed = logline:gets("initiator.command.executed")

    if command_executed:search(mgr_pattern) then
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


-- Функция группера для одного события 4688
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local commands = {}
    local first_event = events[1]
        
    if unique_events > 0 then
        for _, event in ipairs(events) do
            table.insert(commands, event:gets("initiator.command.executed"))
        end
        
        local meta = {
            user=first_event:gets("initiator.user.name"),
            command=string_cut(table.concat(commands, "; ")),
            path=first_event:gets("target.process.path.full"),
            program=first_event:gets("target.image.name"),
            parent=first_event:gets("initiator.process.parent.path.original"),
            ip=first_event:gets("observer.host.ip"),
            hostname=first_event:gets("observer.host.hostname"),
            fqdn=first_event:gets("observer.host.fqdn")
        }

        alert_function(events, meta)
        grouper1:clear()
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

-- Вспомогательная функция логирования значений в функции on_logline
local function log_on_logline(event)
    local event_id = tostring(event:gets("observer.event.id"))
    local command_executed = event:gets("initiator.command.executed")
    log("###  on_logline  ###")
    log("Event ID: " .. event_id)
    log("Command: " .. command_executed:lower())
    log("Pattern: " .. dump_pattern)
    log("Dump file pattern: " .. dump_file_pattern)
    log("Command regex result: " .. tostring(command_executed:lower():search(dump_pattern)))
    log("Dump file: " .. tostring(command_executed:match(dump_file_pattern)))
end

-- Вспомогательная функция логирования значений в функции on_logline для EventID 4688
local function log_on_logline(event)
    local event_id = tostring(event:gets("observer.event.id"))
    log("###  on_logline  ###")
    log("Event ID: " .. event_id)
    
    if compare(event_id, "==", "4688") then
        local command_executed = event:gets("initiator.command.executed") 
        log("Command: " .. command_executed:lower())
        log("Pattern: " .. dump_pattern)
        log("Command regex result: " .. tostring(command_executed:lower():search(dump_pattern)))
    else
        log("Dump file: " .. event:gets("target.object.name"))
    end
end
------------------------------------------------------------------------------------------------------
-- Функция группера для пары типов событий EventID 4104 + EventID 4103
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_scriptblock = {}
    local log_module = {}
    local commands = {}
    local objects = {}
    
    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")

            if compare(event_id, "==", "4104") then
                table.insert(log_scriptblock, event)
                table.insert(commands, event:gets("initiator.command.executed"))
            else
                table.insert(log_module, event)
                table.insert(objects, event:gets("target.object.name"))
            end
        end

        if #log_scriptblock > 0 and #log_module > 1 then
            local first_scriptblock_event = log_scriptblock[1]
            local first_module_event = log_module[1]
            local initiator_name = first_module_event:gets("initiator.user.name")  
            local host_ip = first_scriptblock_event:get("observer.host.ip")
            local host_name = first_scriptblock_event:gets("observer.host.hostname")
            local host_fqdn = first_scriptblock_event:gets("observer.host.fqdn")
            local command_executed = string_cut(table.concat(commands, "; "))
            local objects = string_cut(table.concat(objects, "; "))

            alert_function(events, host_ip, host_name, host_fqdn, initiator_name, command_executed, objects)
            grouper1:clear()
        end
    end
end

-- Функция обработки логлайна для одного типа событий EventID 4688, EventID 4104, EventID 4103
function on_logline(logline)
    local command_executed = logline:gets("initiator.command.executed"):lower()

    if command_executed:search(dump_pattern) then
        grouper1:feed(logline)
    end
end


-- Логируем по EventID
local function log_on_logline(event)
    local process_id = event:gets("observer.process.id")
    log("###  on_logline  ###")
        
    if compare(process_id, "==", "3168") then
        log("Event ID: " .. tostring(process_id))
        local command_executed = event:gets("initiator.command.executed") 
        log("Command: " .. command_executed:lower())
        log("Pattern: " .. threats[2].pattern)
        log("Command regex result: " .. tostring(command_executed:lower():search(threats[2].pattern)))
    end
end

-- Логируем по image
local function log_on_logline(event)
    local target_image = event:gets("target.image.name")
    log("###  on_logline  ###")
        
    if compare(target_image, "==", "powershell.exe") then
        local command_executed = event:gets("initiator.command.executed"):lower() 
        log("Command: " .. command_executed:lower())
        log("Pattern: " .. target_exe)
        log("Command regex result: " .. tostring(command_executed:match('[\"\']((%a:\\[^\"\']+)%.exe)[\'\"\\]*')))
        log("Find MMC: " .. tostring(command_executed:find("slonopotam")))
    end
end