-- Шаблоны алерта
local template = [[
	Подозрение на попытку запуска кода через COM-объект.

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
local grouped_by = {"observer.host.ip", "observer.host.hostname", "target.image.name"}
local aggregated_by = {"operation.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local prefix = "(?:^|\\/|\\s+|\"|\'|\\\\)" 
local com_patterns = {
    prefix.. "regsvr32\\.exe(\\s+\\/\\w+)+:[\"\']?.*[\"\']?\\s+[-\\/\\w\\.\\s]+\\.dll",
    prefix.. "rundll32\\.exe\\s+\\w+\\.dll,\\w+\\s+[\"\']?[\\\\,\\w\\.\\s]+\\.(?:hta|vbs)[\"\']?",
    prefix.. "((?:^|\\s+)reg\\s+add\\s+[\"\']hkey_current_user\\\\[\\\\,\\w\'\"\\w\\/\\s\\.{}-]+(reg_sz\\s+[-\\\\,\\w\\s\\/\'\"{}:\\.]+)?\\/f;)+\\s+rundll32\\.exe\\s+-\\w+[\\s\"\'\\w]+",
    prefix.."((?:^|\\s+)reg\\s+add\\s+\"?\\\\?\"?hkey_current_user[\\\\,\\w\'\"\\\\/\\s\\.{}-]+(reg_sz\\s+[\\\\-\\\\w\\s\\\\/\'\"{}:\\.]+)?\\/f;)+[\\s;]*rundll32\\.exe\\s+-\\w+[\\s\"\'\\w]+",
    prefix.. "(reg\\s+add\\s+\\\\\\\\*\"?hkey_current_user\\\\[^;]+?\\/f;[\\s;]*)+rundll32\\.exe\\s+-\\w+\\s+\\\\\\\\*\"?\\w+\\\\\\\\*\"?",
    prefix.. "(?:excel|word|powerpnt)\\.exe[\'\"]?\\s+\\/automation\\s+-embedding"
}

-- Функция анализа строки
local function analyze(cmd)
    local cmd_string = cmd:lower()
    
    for _, pattern in ipairs(com_patterns) do
        local is_command = cmd_string:search(pattern)
                
        if is_command then 
            return true
        end
    end

    return false
end

-- Функция работы с логлайном
function on_logline(logline)
    local target_path = logline:gets("target.process.path.full")
    local parent_path = logline:gets("initiator.process.parent.path.original")
    local command_executed = logline:gets("initiator.command.executed")
    local path_full = logline:gets("target.process.path.full")
    local image_name = logline:gets("target.image.name")
    parent_path = parent_path:lower()
    target_path = target_path:lower()
    image_name = image_name:lower()
    
    if target_path:match("%.exe$") and parent_path:match("(wmiprvse%.exe)$") or parent_path:match("(mmc%.exe)$") then
        local operation_type = "wmic_com"
        set_field_value(logline,"operation.type", operation_type)
        grouper1:feed(logline)
    elseif path_full:match("(regsvr32%.exe)$") or path_full:match("(cmd%.exe)$") then
        log("Command: " ..command_executed)
        local is_dll = analyze(command_executed)
        
        if is_dll then
            local operation_type = "regsvr32"
            set_field_value(logline,"operation.type", operation_type)
            grouper1:feed(logline)
        end
    elseif path_full:match("(rundll32%.exe)$") or path_full:match("(cmd%.exe)$") then
        log("Command: " ..command_executed)
        local is_dll = analyze(command_executed)
        
        if is_dll then
            local operation_type = "rundll"
            set_field_value(logline,"operation.type", operation_type)
            grouper1:feed(logline)
        end
    elseif image_name == "powershell.exe" or image_name == "pwsh.exe" then
        log("Command: " ..command_executed)
        local is_pwsh_com = analyze(command_executed)

        if is_pwsh_com then
            local operation_type = "posh_wo_com"
            set_field_value(logline,"operation.type", operation_type)
            grouper1:feed(logline)
        end
    else
        local is_com = analyze(command_executed)

        if is_com then
            local operation_type = "com_exec"
            set_field_value(logline,"operation.type", operation_type)
            grouper1:feed(logline)
        end
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
       local command_path = events[1]:get("initiator.process.parent.path.original") or events[1]:get("target.file.path") or events[1]:get("target.image.name") or events[1]:get("event.logsource.application")
       
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
            mitre = {"T1559.001"},
            trim_logs = 10
            }
        )
       grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)