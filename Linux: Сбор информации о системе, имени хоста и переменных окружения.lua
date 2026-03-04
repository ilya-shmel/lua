whitelist = storage.new("wl_hostnames|Linux: Сбор информации о системе, имени узла и переменных окружения")

-- Шаблон алерта
local template = [[
	Обнаружен сбор информации о системе, имени хоста и переменных окружения.  

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]

-- Переменные для групера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Массив с регулярными выражениями
local prefix = "(?:^|\\/|\\s+|\"|\')"
local suffix = "(?:$|\\/|\\s+|\"|\'|;)"
local command_patterns = { 
    prefix .. "(?:ls\\s+-ls?|file|stat|chmod|cat|less|head|tail|lsof|fuser|tar|grep)\\s+(-{1,2}[-\\w:\\s=^\\(\\)\\|]+){0,10}(?:\'|\")?(\\/etc\\/lsb-release|\\/etc\\/redhat-release|\\/etc\\/issue|\\/etc\\/os-release)?(?:\'|\")?" .. suffix,
    prefix .. "(hostname(ctl|\\s+-[a-z])|uname\\s+-[a-z]|uptime(\\s+-[a-z])?|env\\s*\\|\\s*grep)" .. suffix,
    prefix .. "find\\s+\\/[^\\/\\s]+\\s+(-[\\w\\s=:]+){1,10}(?:release|[\\,%,\\w]+)" .. suffix,
    prefix .. "tar\\s+-\\w+(\\s+((\\/?[^\\/\\s]+\\/))?[-\\w]+20\\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|(?:1|2)[0-9]|3[0,1])_(?:(?:0|1)[1-9]|2[0-3])([0-5][0-9]){2}\\.(tar\\.?)?\\w{1,5})+" .. suffix
}


-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()
    
    for _, pattern in pairs(command_patterns) do
        local regular = cmd_string:search(pattern)
        if regular then
            return regular
        end
    end
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    local command_executed = logline:gets("initiator.command.executed")
    
    if event_type == "EXECVE" or event_type == "PROCTITLE" then
		local command_marker = analyze(command_executed)
        if command_marker then
            grouper1:feed(logline)
		end
    else
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local log_sys = ""
    local log_exec = ""

    for _, event in ipairs(events) do
        if event:gets("observer.event.type") == "SYSCALL" then
            log_sys = event
        else
            log_exec = event
        end
    end

-- Проверяем, что в группере находятся как события EXECVE/PROCTITLE, так и SYSCALL        
    if log_sys ~= "" and log_exec ~= "" then
        local host_name = log_exec:gets("observer.host.hostname")
        local host_check = whitelist:get(host_name, "hostname") 
        
        if not host_check then    
            local user_name = log_sys:gets("initiator.user.name")
            local host_ip = log_exec:gets("observer.host.ip")
            local host_fqdn = log_exec:gets("observer.host.fqdn")
            local initiator_name = log_sys:gets("initiator.user.name")
            local path_name = log_sys:gets("initiator.process.path.full")
            local command_executed = log_exec:gets("initiator.command.executed")
            
            if command_executed and #command_executed > 128 then
                command_executed = command_executed:sub(1,128)
            end
            -- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command_path=path_name,
                    command=command_executed
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
                command=command_executed,
                logs = grouped.aggregatedData.loglines,
                mitre = {"T1082", "T1087"},
                trim_logs = 10
                }
            )
            grouper1:clear()
        end
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)