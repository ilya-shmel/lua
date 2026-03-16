-- Шаблоны алерта
local template = [[
	Обнаружено извлечение данных учетных записей с отключенной предварительной аутентификацией в Kerberos.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь (инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.path }}
]]

-- Переменные для группера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}
local aggregated_by = {"initiator.user.name"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local pwn_pattern = "(?:^|\\/|\\s+|\"|\'|{)((iex\\(new-object|import-module)(.+)(?:winpwn\\.ps1|powersharp(.+)(?:rubeus|Internalmonologue|seatbelt|sharpup)\\.ps1)|spoolvulnscan|MS17-10|bluekeep|fruit)(?:$|\\/|\\s+|\"|\'|})"

-- Функция анализа строки
local function analyze(cmd)
    local cmd_string = cmd:lower()
    local is_command = cmd_string:search(pwn_pattern)

    if is_command then 
        return true
    end
    
    return false
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")

    
    if event_id == 4768 then
       grouper1:feed(logline) 
    elseif 
        local command_executed = logline:gets("initiator.command.executed")
        local is_pwn = analyze(command_executed)
    end
    
    if is_pwn then
       grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    log("Events: " ..#events)
    if #events > 0 then
       local initiator_name = events[1]:get("initiator.user.name") or "Пользователь не определен" 
       local host_ip = events[1]:get_asset_data("observer.host.ip")
       local host_name = events[1]:get_asset_data("observer.host.hostname")
       local host_fqdn = events[1]:get_asset_data("observer.host.fqdn")
       local command_executed = events[1]:gets("initiator.command.executed")
       local command_path = events[1]:get("initiator.process.parent.path.original") or events[1]:get("target.process.path.full") or events[1]:get("target.image.name") or events[1]:get("event.logsource.application")
       
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
            risk_level = 6.0, 
            asset_ip = host_ip,
            asset_hostname = host_name,
            asset_fqdn = host_fqdn,
            asset_mac = "",
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "",
            logs = events,
            mitre = {"T1558.004"},
            trim_logs = 10
            }
        )
       grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)