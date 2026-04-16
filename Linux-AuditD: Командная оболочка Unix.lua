-- Шаблоны алерта
local template = [[
	Обнаружена аномальная активность Unix Shell.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]

local detection_window = "1m"
local grouped_time_field = "@timestamp,RFC3339"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}

local prefix = "(?:^|\\/|\\s+|\"|\')"
local threat_patterns = {
    prefix .."(\"?(\\w{1,3})?sh\\b\\s+-(?:c|i)\\s+){1,2}(?:>&\\s+\\/dev\\/tcp\\/(\\d{1,3}\\.){3}\\d{1,3}\\/\\d{2,8}(\\s+[\\d>&\"]+)?|cat\\s+\\/etc\\/shells)",
    prefix .."nc(at)?\\s+-(?:e|l)\\s+\\/bin\\/\\w{1,3}?sh\\s+(\\d{1,3}\\.){3}\\d{1,3}\\s+(?:\\d|[a-z]){2,8}",
    prefix .."base64\\b\\s+-d\\s+|\\s+(\\/bin)?\\w{1,3}?sh(\\s+-(?:i|s))?",
    prefix .."(?:\\w{0,3}sh\\b\\s+-c|eval)\\s+[^\\|]+\\|\\s+base64\\s+-d[\\s|$|\\)|\"|\'|]{1,2}\\s+bash\\s+-(?:s|i)",
    prefix .."eval\\s+(?:\\$\\(\\|\\`)",
    prefix .."exec\\s+\\d[<>]{1,2}(\\s+)?\\/dev\\/tcp\\/(\\d{1,3}\\.){3}\\d{1,3}\\/\\d{2,8}",
    prefix .."\\bpython\\d+(?:.\\d+)?\\s+-c\\s+([\'\"])?[^\'\"]*?socket\\.socket\\(\\)([\'\"])?",
    prefix .."\\bmkfifo\\s+(\\/[^\\/\\s]*)+\\s+\\|\\s+[^>]+[<>]{1}\\s+(\\/[^\\/\\s]*)+\\s+[\\|&]{1,2}\\s+nc(at)?\\s+(?:\\w{1,32}\\.\\w{1,12}\\.\\w{1,5}|(\\d{1,3}\\.){3}\\d{1,3})\\s+\\d{2,8}",
    prefix .."\\bperl\\s+([-\\w:]+\\s+)+[\'\"]?(use\\s+socket;\\s+)?[-\\w\\s$=:;\\,\\(\\)<>]+[\'\"]?",
    prefix .."(?:curl\\b|wget\\b)\\s+(?:\"|\')?(?:www|http(s)?)\\/{0,2}[^\\s]+[\\w\\?#\\/](?:\"|\')\\s+\\|\\s+\\w{0,3}sh\\b"
}

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()
    
    for _, pattern in ipairs(threat_patterns) do
        local is_unix_anomaly = cmd_string:search(pattern)

        if is_unix_anomaly then
            return is_unix_anomaly
        end
    end
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
        
    if event_type == "EXECVE" or event_type == "PROCTITLE" then
        local command_executed = logline:gets("initiator.command.executed")
		local threat_marker = analyze(command_executed)
        
        if threat_marker then
            grouper1:feed(logline)
        end
    elseif event_type == "SYSCALL" then
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_sys = nil
    local log_exec = nil

    if unique_events > 1 then
        for _, event in ipairs(events) do
            event_type = event:gets("observer.event.type") 
            if event_type == "SYSCALL" then
                log_sys = event
            else
                log_exec = event
            end
        end

-- Проверяем, что в группере находятся как события EXECVE, так и SYSCALL        
        if log_sys and log_exec then
            local initiator_name = log_sys:gets("initiator.user.name")
            local host_ip = log_exec:gets("observer.host.ip")
            local host_fqdn = log_exec:gets("observer.host.fqdn")
            local path_name = log_sys:gets("initiator.process.path.full")
                
-- Объединить все зафиксированные команды в одну строку и обрезать её для наглядного вывода в карточке инцидента                
            local current_command = log_exec:gets("initiator.command.executed")
            
            if #current_command > 128 then
                current_command = current_command:sub(1,128).. "... "
            end 
              
-- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command_path=path_name,
                    command=current_command
                },
                risk_level = 7.0, 
                asset_ip = host_ip,
                asset_hostname = host_name,
                asset_fqdn = host_fqdn,
                asset_mac = "",
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                command=command_executed,
                logs = events,
                mitre = {"T1059.004", "T1059", "T1027"},
                trim_logs = 12
                }
            )
            grouper1:clear()      
        end
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)
