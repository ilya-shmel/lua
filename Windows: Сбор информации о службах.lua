-- Шаблон алерта
local template = [[
Обнаружен сбор информации о службах.

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
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "initiator.process.parent.id", "event.rule.description"}
local aggregated_by = {"target.image.name"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local service_patterns = {   
    SERVICE_LIST = {
        pattern = [[(?:^|\/|\s+|"|'|\()(?:sc(\.exe)\s+query|tasklist(\.exe))(?:$|\/|\s+|"|'|\))(?:state=[\s\S]*|\/svc)?]],
        name = "system service discovery"
    },
    
    DULL = {
        pattern = [[(?:^|\/|\s+|"|'|\()dull(?:$|\/|\s+|"|'|\))]],
        name = "dull"
    }
}

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

-- Функция сортировки таблиц
local function get_unique_elements(input_array)
    local hash_table = {}    -- Временная таблица для отслеживания "увиденных" элементов
    local result_table = {}  -- Новый массив с уникальными значениями

    for _, element in ipairs(input_array) do
-- Если мы еще не встречали такое значение
        local is_odd = check_empty_field(element)
        if is_odd then
            element = is_odd
        end

        if not hash_table[tostring(element)] then
            table.insert(result_table, tostring(element)) -- Добавляем в результат
            hash_table[element] = true          -- Помечаем как "увиденное"
        end
    end

    return result_table
end

-- Функция алерта
local function alert_function(events, ip, hostname, fqdn, user, cmd, program, parent, path)
    alert({
        template = template,
        meta = {
            user=user,
            command=cmd,
            path=path,
            program=program,
            parent=parent,
            ip=ip,
            hostname=hostname,
            fqdn=fqdn
            },
        risk_level = 8.0, 
        asset_ip = ip,
        asset_hostname = hostname,
        asset_fqdn = fqdn,
        asset_mac = "",
        create_incident = true,
        incident_group = "",
        assign_to_customer = false,
        incident_identifier = "",
        logs = events,
        mitre = {"T1007"},
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
local function analyze(cmd, pattern)
    local cmd_lower = cmd:lower()

    if cmd_lower:search(pattern) then
            return true
    end

    return false
end

-- Функция обработки логлайна
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")
    
    if compare(event_id, "==", "4688") then
        local image_name = logline:gets("target.image.name")
        local command_executed = logline:gets("initiator.command.executed")

        if image_name == "sc.exe" or image_name == "tasklist.exe" then 
            if analyze(command_executed, service_patterns.SERVICE_LIST.pattern) then
                set_field_value(logline, "event.rule.description", service_patterns.SERVICE_LIST.name)
                grouper1:feed(logline)
            end
        end
    end
end

-- Функция группера #1
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local first_event = events[1]
    local commands = {}
    local target_images = {}
    local paths = {}
    
    log_grouper(events, #events, unique_events, "on_grouped", grouped_by[4])

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local command_executed = event:gets("initiator.command.executed")
            local image_name = event:gets("target.image.name")
            local process_path = event:gets("target.process.path.full")
            table.insert(commands, command_executed)
            table.insert(target_images, image_name)
            table.insert(paths, process_path)
        end

        if #commands > 1 then
            local initiator_name = first_event:gets("initiator.user.name")  
            local host_ip = first_event:get("observer.host.ip")
            local host_name = first_event:gets("observer.host.hostname")
            local host_fqdn = first_event:gets("observer.host.fqdn")
            local initiator_path = first_event:get("initiator.process.parent.path.original")
            local command_executed = string_cut(table.concat(commands, "; "))
            local program_name = table.concat(get_unique_elements(target_images), "; ")
            local target_path = table.concat(get_unique_elements(paths), "; ")

            alert_function(events, host_ip, host_name, host_fqdn, initiator_name, command_executed, program_name, initiator_path, target_path)
            grouper1:clear()
        end

    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)