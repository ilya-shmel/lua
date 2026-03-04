-- Шаблоны алерта
local template1 = [[
	Обнаружены ошибки NTFS.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Путь к файлу: {{ .Meta.path }}
    Код ошибки: {{ if .First.event.error.code }}{{ .First.event.error.code }}{{ else }}"Код ошибки неопределен"{{ end }}
    Описание ошибки: {{ if .First.event.description }}{{ .First.event.description }}{{ else }}"Ошибка файловой системы"{{ end }}
]]

local template2 = [[
	Обнаружены ошибки NTFS - опасное выполнение команд.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь (инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.path }}
]]

-- Переменные для группера
local detection_window = "5m"
local grouped_by1 = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}
local grouped_by2 = {"observer.host.ip", "observer.host.hostname", "target.image.name"}
local aggregated_by1 = {"observer.event.id"}
local aggregated_by2 = {"observer.process.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local prefix = "(?:^|\\/|\\s+|\"|\'|\\\\)" 
local regex_patterns = {
    prefix.. "format\\s+\\w:\\s+\\/fs:\\w+",
    prefix.. "diskpart\\s+>\\s+clean",
    prefix.. "(?:clear-disk(?:\\s+-removedata)?|initialize-disk|remove-partition)(\\s+-\\w+(\\s+\\d+)?){0,10}",
    prefix.. "(?:sdelete|cipher)\\s+[-\\/:\\w\\s]+",
    prefix.. "invoke-wmimethod(\\s+[-.\\w$]+path){2}(\\s+-\\w+\\s+(?:format|[\'\"]ntfs[\'\"]))+(,[$\\w\'\"]+)+",
    prefix.. "format-volume\\s+-driveletter\\s+(\\$\\w+\\.[\\w():\'\",]+)\\s+-filesystem\\s+ntfs\\s+(-[\\w:$@=]+){0,10}",
    prefix.. "eraser(l)?(\\.exe)?[\'\"\\\\]+\\s+\\/task\\s+[\'\"\\\\]+[^\'\"\\\\]+[\'\"\\\\]+",
    prefix.. "dd(\\s+(?:if|of)=\\/dev\\/\\w+){2}(\\s+?[\\w=]+)?",
    prefix.. "shred(\\s+-\\w+)+(\\s+\\d)?\\s+(\\/?[^\\/\\s]+\\/)?[^\\/\\s]+",
    prefix.. "(?:fdisk|parted|mkfs|wipefs)(\\.\\w+)?(\\s+-\\w+)?\\s+\\/dev\\/\\w+",
    prefix.. "bcwipe(\\.exe)?\\s+[^:.]+[:.](\\\\)+[^$]+"    
}

-- Функция анализа строки
local function analyze(cmd)
    local cmd_string = cmd:lower()

    for _, pattern in ipairs(regex_patterns) do
        local is_command = cmd_string:search(pattern)
        
        if is_command then 
            return true
        end
    end

    return false
end

-- Проверка на случай, если в событии вместо строки указано `[]`, или `{}`, или элемент принимает тип "Таблица"
local function check_empty_field(field)
    if field == "[]" or field == "{}" or field == "" or field:match("table:") then
        field = "Не определен"
        return field
    end
    
    return nil
end

-- Функция выборки уникальных значений в массиве
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
local function alert_function(template, cmd, user, path, ip, hostname, fqdn, events)
    
    if #cmd > 128 then
        cmd = cmd:sub(1,128).. "..."
    end

    alert({
            template = template,
            meta = {
                user_name=user,
                command=cmd,
                path=path
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
            mitre = {"T1561"},
            trim_logs = 10
            }
        )
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    local source_vendor = logline:gets("event.logsource.vendor")
    
    if event_type == "system" and source_vendor == "microsoft" then
        grouper1:feed(logline)
    else
        local command_executed = logline:gets("initiator.command.executed")
        local is_command = analyze(command_executed)
        
        if is_command then
            grouper2:feed(logline)
        end
    end
       
end

-- Функция сработки группера #1
function on_grouped1(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local file_path = {}
    
    if unique_events > 1 or #events > 4 then
        for _, event in ipairs(events) do
            local error_path = event:gets("target.file.path")
            table.insert(file_path, error_path)
        end
       
        file_path = get_unique_elements(file_path)
        local all_paths = table.concat(file_path, "; ")
        local host_ip = events[1]:get_asset_data("observer.host.ip")
        local host_name = events[1]:get_asset_data("observer.host.hostname")
        local host_fqdn = events[1]:get_asset_data("observer.host.fqdn"),
        alert_function(template1, "no command", "no user", all_paths, host_ip, host_name, host_fqdn, events)
        grouper1:clear()
    end
end

-- Функция сработки группера #2
function on_grouped2(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total

    if #events > 0 then
        local user_name = events[1]:gets("initiator.user.name")
            
            if user_name:match("^%S") > 0 then
                local initiator_name = user_name
            else 
                local initiator_name = "Пользователь неопределен"
            end
    end
       
       local host_ip = events[1]:get_asset_data("observer.host.ip")
       local host_name = events[1]:get_asset_data("observer.host.hostname")
       local host_fqdn = events[1]:get_asset_data("observer.host.fqdn")
       local command_executed = events[1]:gets("initiator.command.executed")
       local command_path = events[1]:get("target.process.path.full") or events[1]:get("target.file.path") or events[1]:get("target.image.name") or events[1]:get("event.logsource.application")
       alert_function(template2, command_executed, initiator_name, command_path, host_ip, host_name, host_fqdn, events)
       grouper1:clear()
end

grouper1 = grouper.new(grouped_by1, aggregated_by1, grouped_time_field, detection_window, on_grouped1)
grouper2 = grouper.new(grouped_by2, aggregated_by2, grouped_time_field, detection_window, on_grouped2)