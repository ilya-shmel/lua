-- Шаблон алерта
local template = [[
	Обнаружена попытка получить реквизиты доступа Kubernetes.
	Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]

local prefix = "(?:^|\\/|\\s+|\"|\')"
local suffix = "(?:$|\\/|\\s+|\"|\')"
local secrets_patterns = {
prefix .. "kubectl\\s+(?:get\\s+secret(s)?|describe\\s+secret(s)?)(\\s+)?([a-z](?:[-\\.\\w]*[-\\.\\w])?)?((-{1,2}[\\s\\w=:\'{}}\\.|]+)+)?" .. suffix,
prefix .. "(?:docker\\s+exec\\s+k\\ds-api-container|kubectl\\s+-{1,2}(?:c(=)?|context)\\s+?[-\\w]+\\s+exec\\s+[-\\w]+\\s+--)\\s+(?:cat|less|more|head|tail)\\s+(-{1,2}[\\w\\s]+)?(\\/\\S+)?\\/secret(s)?(\\/\\S+)?" .. suffix,
prefix .. "k\\ds\\ssecrets(\\/\\S+)?\\s+-{1,2}(?:all(-namespaces)?|namespace|(yaml|json)|output|(?:n(s)?|o|y|j|A))(\\s+\\S+)?" .. suffix
}

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze_cmd(cmd)
    local cmd_lower = cmd:lower()
    
    for _, pattern in ipairs(secrets_patterns) do
        local is_regex = cmd_lower:search(pattern)
        if is_regex then
            return is_regex
        end
    end
end

-- Функция очистки null bytes
local function clean(cmd)
    local cleaned_cmd = string.gsub(cmd, "%z", " ")
    cleaned_cmd = string.gsub(cleaned_cmd, "%s+", " ")
    return string.match(cleaned_cmd, "^%s*(.-)%s*$") or cleaned_cmd
end

-- Функция обработки логлайна
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    local syscall_name = logline:gets("target.syscall.name")

    if event_type == "EXECVE" or event_type == "PROCTITLE" then
		local command_executed = logline:gets("initiator.command.executed")
        command_executed = clean(command_executed)
        local is_secrets = analyze_cmd(command_executed)

        if is_secrets then
            grouper1:feed(logline)
        end
    elseif event_type == "SYSCALL" and syscall_name == "execve" then
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
	local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    
    if unique_events > 1 then
		local log_exec = nil
        local log_sys = nil
		
        for _, event in ipairs(events) do
			local event_type = event:gets("observer.event.type")
            if event_type == "SYSCALL" then
				log_sys = event
			else
				log_exec = event
            end
		end
        
        if log_sys and log_exec then
           local command_executed = log_exec:gets("initiator.command.executed")
           local executed_path = log_sys:gets("initiator.process.path.full")
           local initiator_name = log_sys:gets("initiator.user.name")
           local host_ip = log_sys:get_asset_data("observer.host.ip")
           local host_name = log_sys:get_asset_data("observer.host.hostname")
           local host_fqdn = log_sys:get_asset_data("observer.host.fqdn") 
                
-- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command=command_executed,
                    command_path=executed_path,
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
                mitre = {"T1552.007", "T1526"},
                trim_logs = 10
                }
            )
            grouper1:clear()
        end    
    end    
end

-- Группер
grouper1 = grouper.new({"observer.host.ip", "observer.host.hostname", "observer.event.id"}, {"observer.event.type"}, "@timestamp,RFC3339", "1m", on_grouped)