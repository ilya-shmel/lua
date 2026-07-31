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
Процесс-инициатор: {{ .Meta.initiator }}
Целевой процесс: {{ .Meta.target }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by1 = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "observer.process.id", "event.process.id"}
local grouped_by2 = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "observer.process.id", "target.command.executed"}
local aggregated_by = {"target.image.name"}
local grouped_time_field = "@timestamp,RFC3339"

-- Паттерны и регулярные выражения
local target_exe = '[\"\']((%a:\\[^\"\']+)%.exe)[\'\"\\]*'

-- Вспомогательная функция логирования значений в группере (удалить после тестирования на потоке)
local function log_grouper(events, events_number, unique_events, grouper_name, grouper_field)
    log("### " .. grouper_name .. " ###")
    log("Events: " ..#events.. ". Unique events: " ..unique_events)
    
    for _, event in ipairs(events) do
	    log("Event ID: " .. tostring(event:gets("observer.event.id")))
        log("PID: " .. tostring(event:gets("observer.process.id")))
        log("Grouper field: " .. tostring(event:gets(grouper_field)))
        log("Aggregated by: " .. event:gets("target.image.name"))
        log("Command type: " .. event:gets("event.rule.description"))
        log("Command executed: " .. event:gets("initiator.command.executed")) 
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
        log("PID: " .. tostring(event:gets("observer.process.id")))
        log("Command regex result: " .. tostring(command_executed:match('[\"\']((%a:\\[^\"\']+)%.exe)[\'\"\\]*')))
        log("Find MMC: " .. tostring(command_executed:find("slonopotam")))
    end
end

-- Функция удаления невидимых символов
local function normalize_path(path)
        path = path:lower()                             -- Приводим к нижнему регистру
        path = path:gsub('["\']', '')                   -- Удаляем все кавычки (одинарные и двойные)
        path = path:gsub('\\+$', '')                    -- Удаляем обратные слеши в конце (если есть)
        path = path:gsub('^%s+', ''):gsub('%s+$', '')   -- Удаляем лишние пробелы
    return path
end

-- Функция алерта
local function alert_function(events, meta)
    alert({
        template = template,
        meta = meta,
        risk_level = 7.5, 
        asset_ip = meta.ip,
        asset_hostname = meta.hostname,
        asset_fqdn = meta.fqdn,
        asset_mac = "",
        create_incident = true,
        incident_group = "",
        assign_to_customer = false,
        incident_identifier = "",
        logs = events,
        mitre = {"T1021.003"},
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

-- Функция обработки логлайна для одного события 4688
function on_logline(logline)
--    log_on_logline(logline)
    local target_image = logline:gets("target.image.name")
    local command_executed = logline:gets("initiator.command.executed"):lower()

    if target_image == "mmc.exe" then
        set_field_value(logline, "event.process.id", logline:gets("target.process.id"))
        set_field_value(logline, "event.rule.description", "lateral initiator")
        grouper1:feed(logline)
    elseif command_executed:match(target_exe) and command_executed:find("mmc20.application") then
        local target_path = normalize_path(command_executed:match(target_exe)) 
        set_field_value(logline, "target.command.executed", target_path)
        set_field_value(logline, "event.rule.description", "lateral command")
        grouper2:feed(logline)
    else        
        set_field_value(logline, "event.process.id", logline:gets("initiator.process.parent.id"))
        set_field_value(logline, "event.rule.description", "lateral target")
        grouper1:feed(logline)
    end
end

-- Функция группера #1
function on_grouped1(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_init, log_target
    
--    log_grouper(events, #events, unique_events, "on_grouped1", grouped_by1[5])
    
    if unique_events > 1 then
        for _, event in ipairs(events) do
            if event:gets("event.rule.description") == "lateral initiator" then
                log_init = event
            else
                log_target = event
            end
        end

        local target_command = normalize_path(log_target:gets("initiator.command.executed"))
        set_field_value(log_init, "target.command.executed", target_command)
        set_field_value(log_target, "target.command.executed", target_command)
        grouper2:feed(log_init)
        grouper2:feed(log_target)
        grouper1:clear()
    end
end

-- Функция группера #2
function on_grouped2(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_init, log_target, log_exec 
        
    log_grouper(events, #events, unique_events, "on_grouped2", grouped_by2[5])

    if unique_events > 2 then
        for _, event in ipairs(events) do
            if event:gets("event.rule.description") == "lateral initiator" then
                log_init = event
            elseif event:gets("event.rule.description") == "lateral target" then
                log_target = event
            else
                log_exec = event
            end
        end

        if log_init and log_target and log_exec then
            log("All events in grouper")
            local meta = {
                user=log_exec:gets("initiator.user.name"),
                command=string_cut(log_exec:gets("initiator.command.executed")),
                path=log_exec:gets("target.process.path.full"),
                program=log_exec:gets("target.image.name"),
                parent=log_exec:gets("initiator.process.parent.path.original"),
                initiator=log_init:gets("target.image.name"),
                target=log_target:gets("target.image.name"),
                ip=log_init:gets("observer.host.ip"),
                hostname=log_init:gets("observer.host.hostname"),
                fqdn=log_init:gets("observer.host.fqdn"),
                title="Латеральное перемещение через DCOM/PowerShell"
        }
        
            alert_function(events, meta)
            grouper2:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by1, aggregated_by, grouped_time_field, detection_window, on_grouped1)
grouper2 = grouper.new(grouped_by2, aggregated_by, grouped_time_field, detection_window, on_grouped2)