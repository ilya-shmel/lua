-- Шаблоны алерта
local template = [[
	Обнаружено отключение одной или нескольких служб через реестр Windows.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь (инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.path }}
]]

local command_types = {
    [1] = "hklm",
    [2] = "hkcu",
    [3] = "pwsh"
}

-- Переменные для группера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "operation.type"}
local aggregated_by = {"target.image.name"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local prefix = "(?:^|\\/|\\s+|\"|\'|\\\\)" 
local regex_patterns = {
    prefix.. "reg\\s+add\\s+[\"\']?hklm\\\\(?:system|software)\\\\[^\\/]+\\/\\w+\\s+(?:runasppl|(complus_)?(etw)?enabled)\\s+\\/t\\s+reg_(?:dword|sz)\\s+\\/d\\s+0",
    prefix.. "(reg add)\\s+hkcu\\\\environment\\s+\\/v\\s+complus_etwenabled\\s+\\/t\\s+reg_(?:dword|sz)\\s+\\/d\\s+0",
    prefix.. "new-itemproperty\\s+(-path\\s+)?[\"\']?hk(?:lm|cu):\\D{5,200}[\"\']?\\s+-name(\\s+\\D{5,20}){1,2}\\s+-value\\s+0"
}

-- Функция анализа строки
local function analyze(cmd)
    local cmd_string = cmd:lower()
    local index = 0
    for _, pattern in ipairs(regex_patterns) do
        local is_command = cmd_string:search(pattern)
        index = index + 1
        
        if is_command then 
            return true, index
        end
    end

    return false
end

-- Функция работы с логлайном
function on_logline(logline)
    local command_executed = logline:gets("initiator.command.executed")
    local is_command, index = analyze(command_executed)
    operation_type = command_types[index]
    set_field_value(logline,"operation.type", operation_type)

    if is_command then
       grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines

    if #events > 0 then
       local initiator_name = events[1]:get("initiator.user.name") or "Пользователь не определен" 
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
            mitre = {"T1562"},
            trim_logs = 10
            }
        )
       grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)