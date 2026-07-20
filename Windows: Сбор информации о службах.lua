-- Шаблон алерта
local template1 = [[
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
Родительский процесс: {{ .Meta.parent }}
]]

local template2 = [[
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
Родительский процесс: {{ .Meta.parent }}
Результирующий файл: {{ or .Meta.file "Имя файла не определено" }}
]]

local template3 = [[
Обнаружен сбор информации о службах.

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{ or .Meta.ip "IP-адрес не определён" }}
Узел: {{ or .Meta.hostname "Имя узла не определено" }}
FQDN: {{ or .Meta.fqdn "FQDN узла не определено" }}

ИНИЦИАТОР:
Пользователь: {{ or .Meta.user "Пользователь не определён"}}

ВЫПОЛНЕННАЯ КОМАНДА:
{{ .Meta.command }}
Командлет: {{ .Meta.program }}
Запрашиваемые объекты: {{ or .Meta.file "Имя объекта не определено" }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_time_field = "@timestamp,RFC3339"

local grouped_by1 = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "initiator.process.parent.id", "event.rule.description"}
local aggregated_by1 = {"target.image.name"}
local grouped_by2 = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "event.process.id"}
local aggregated_by2 = {"observer.event.id"}
local grouped_by3 = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "target.image.name"}
local aggregated_by3 = {"observer.event.id"}
local grouped_by4 = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "observer.process.id"}
local aggregated_by4 = {"observer.event.id"}

-- Регулярные выражения
local service_patterns = {   
    SERVICE_LIST = {
        pattern = [[(?:^|\/|\s+|"|'|\()(?:sc(\.exe)?\s+query|tasklist(\.exe)?)(?:$|\/|\s+|"|'|\))(?:state=[\s\S]*|\/svc)?]],
        name = "system service discovery"
    },
    NET_EXE = {
        pattern = [[(?:^|\/|\s+|"|'|\()net(\.exe)?(?:$|\/|\s+|"|'|\))start([\s>]+\w:(\\?[^\\]+)*\.\w{1,5})?]]
        },
    ENUMERATE = { 
        pattern = [[(?:^|\/|\s+|"|'|\()(?:get-service|schtasks[\s\S]*list)(?:$|\/|\s+|"|'|\))]]
    },
    SERVICES_REGISTRY = {
        pattern = [[(?:^|\/|\s+|"|'|\()get-[^\s]+\s+[^:'"]+['"]?hk\w{1,2}:(\\[^\\]+)+\\services(?:$|\/|\s+|"|'|\))]],
        object_pattern = "HK[%w_]+[\\%w]+Services\\([^\\]+)"
    }
    
}

-- Проверка на случай, если в событии вместо строки указано `[]`, или `{}`, или элемент принимает тип "Таблица"
local function check_empty_field(field)
    if field == "[]" or field == "{}" or field == "" or field:match("table:") then
        field = "Не определен"
        return field
    end
    
    return nil
end

-- Функция сортировки таблиц
local function get_unique_elements(input_array)
    local hash_table = {}    -- Временная таблица для отслеживания "увиденных" элементов
    local result_table = {}  -- Новый массив с уникальными значениями

    for _, element in ipairs(input_array) do
        local is_odd = check_empty_field(element) -- Если мы еще не встречали такое значение
        
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
local function alert_function(template, events, ip, hostname, fqdn, user, cmd, program, parent, path, file)
    alert({
        template = template,
        meta = {
            user=user,
            command=cmd,
            path=path,
            program=program,
            parent=parent,
            file=file,
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
        elseif image_name == "net.exe" or image_name == "cmd.exe" then
            if analyze(command_executed, service_patterns.NET_EXE.pattern) then
                set_field_value(logline, "event.process.id", logline:gets("target.process.id"))
                grouper2:feed(logline)
            end
        elseif image_name == "powershell.exe" or image_name == "schtasks.exe" then
            --
            if analyze(command_executed, service_patterns.ENUMERATE.pattern) then
                grouper3:feed(logline)
            end
        end
    elseif compare(event_id, "==", "4663") then
        set_field_value(logline, "event.process.id", logline:gets("initiator.process.id"))
        grouper2:feed(logline)
    elseif compare(event_id, "==", "4104") then
        local command_executed = logline:gets("initiator.command.executed")
        
        if analyze(command_executed, service_patterns.SERVICES_REGISTRY.pattern) then
            grouper4:feed(logline)
        end
    elseif compare(event_id, "==", "4103") then
        grouper4:feed(logline)
    end
end

-- Функция группера #1
function on_grouped1(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local first_event = events[1]
    local commands = {}
    local target_images = {}
    local paths = {}
    
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

            alert_function(template1, events, host_ip, host_name, host_fqdn, initiator_name, command_executed, program_name, initiator_path, target_path, "")
            grouper1:clear()
        end

    end
end

-- Функция группера #2
function on_grouped2(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec, log_file    

    if unique_events > 1 then
        for _, event in ipairs(events) do
            if compare(event:gets("observer.event.id"), "==", "4688") then
                log_exec = event
            else
                log_file = event
            end
        end

        if log_exec and log_file then
            local initiator_name = log_exec:gets("initiator.user.name")  
            local host_ip = log_exec:get("observer.host.ip")
            local host_name = log_exec:gets("observer.host.hostname")
            local host_fqdn = log_exec:gets("observer.host.fqdn")
            local process_path = log_exec:gets("target.process.path.full")
            local parent_path = log_exec:gets("initiator.process.parent.path.original")
            local command_executed = string_cut(log_exec:gets("initiator.command.executed"))
            local program_name = log_exec:gets("target.image.name")
            local file_path = log_file:gets("target.object.name")

            alert_function(template2, events, host_ip, host_name, host_fqdn, initiator_name, command_executed, program_name, parent_path, process_path, file_path)
            grouper2:clear()
        end

    end
end

function on_grouped3(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local first_event = events[1]    

    if #events > 0 then
        local initiator_name = first_event:gets("initiator.user.name")  
        local host_ip = first_event:get("observer.host.ip")
        local host_name = first_event:gets("observer.host.hostname")
        local host_fqdn = first_event:gets("observer.host.fqdn")
        local process_path = first_event:gets("target.process.path.full")
        local parent_path = first_event:gets("initiator.process.parent.path.original")
        local command_executed = string_cut(first_event:gets("initiator.command.executed"))
        local program_name = first_event:gets("target.image.name")

        alert_function(template1, events, host_ip, host_name, host_fqdn, initiator_name, command_executed, program_name, parent_path, process_path, "")
        grouper3:clear()
    end
end

function on_grouped4(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_scriptblock
    local log_modules = {}
    local target_objects = {}

    if unique_events > 1 then
        for _, event in ipairs(events) do
            if compare(event:gets("observer.event.id"), "==", "4104") then
                log_scriptblock = event
            else
                table.insert(log_modules, event)
                local target_object = event:gets("target.object.name")
                local object_name = target_object:match(service_patterns.SERVICES_REGISTRY.object_pattern)
                table.insert(target_objects, (event:gets("target.object.name"):match(service_patterns.SERVICES_REGISTRY.object_pattern)))
            end
        end

        if log_scriptblock and #log_modules > 2 then
            local initiator_name = log_modules[1]:gets("initiator.user.name")  
            local host_ip = log_scriptblock:get("observer.host.ip")
            local host_name = log_scriptblock:gets("observer.host.hostname")
            local host_fqdn = log_scriptblock:gets("observer.host.fqdn")
            local command_executed = string_cut(log_scriptblock:gets("initiator.command.executed"))
            local program_name = log_scriptblock:gets("initiator.process.command")
            local target_object = string_cut(table.concat(target_objects, "; "))

            alert_function(template3, events, host_ip, host_name, host_fqdn, initiator_name, command_executed, program_name, "", "", target_object)
            grouper3:clear()
        end
    end    
end

grouper1 = grouper.new(grouped_by1, aggregated_by1, grouped_time_field, detection_window, on_grouped1)
grouper2 = grouper.new(grouped_by2, aggregated_by2, grouped_time_field, detection_window, on_grouped2)
grouper3 = grouper.new(grouped_by3, aggregated_by3, grouped_time_field, detection_window, on_grouped3)
grouper4 = grouper.new(grouped_by4, aggregated_by4, grouped_time_field, detection_window, on_grouped4)