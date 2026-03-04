-- Шаблоны алерта
local template = [[
	Обнаружена попытка затирание файла, раздела диска, диска.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь (инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.path }}
]]

-- Переменные для группера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "target.image.name"}
local aggregated_by = {"observer.process.id"}
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
    
    return field
end

-- Функция выборки уникальных значений в массиве
local function get_unique_elements(input_array)
    local hash_table = {}    
    local result_table = {}  

    for _, element in ipairs(input_array) do
        local is_odd = check_empty_field(element)
        if is_odd then
            element = is_odd
        end

        if not hash_table[tostring(element)] then
            table.insert(result_table, tostring(element)) 
            hash_table[element] = true         
        end
    end

    return result_table
end

-- Функция работы с логлайном
function on_logline(logline)
    local command_executed = logline:gets("initiator.command.executed")
    local is_command = analyze(command_executed)
        
    if is_command then
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    
    if #events > 0 then
       local user_name = events[1]:gets("initiator.user.name")
       local initiator_name = check_empty_field(user_name)
       local host_ip = events[1]:get_asset_data("observer.host.ip")
       local host_name = events[1]:get_asset_data("observer.host.hostname")
       local host_fqdn = events[1]:get_asset_data("observer.host.fqdn")
       local command_executed = events[1]:gets("initiator.command.executed")
       local command_path = events[1]:get("target.process.path.full") or events[1]:get("target.file.path") or events[1]:get("target.image.name") or events[1]:get("event.logsource.application")
       
       if #command_executed > 128 then
            command_executed = command_executed:sub(1,128).. "..."
       end
       
       alert({
            template = template,
            meta = {
                user_name=initiator_name,
                command=command_executed,
                path=command_path
                },
            risk_level = 8.0, 
            asset_ip = host_ip,
            asset_hostname = host_name,
            asset_fqdn = host_fqdn,
            asset_mac = "",
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "",
            logs = events,
            mitre = {"T1561.001", "T1561.002"},
            trim_logs = 10
            }
        )
       grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)