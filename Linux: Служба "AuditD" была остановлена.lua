-- Шаблон алерта
local template = [[
	Подозрение на остановку службы auditd.
	Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]

-- Массив с регулярными выражениями
local prefix = "(?:^|\\/|\\s+|\"|\')"
local suffix = "(?:$|\\/|\\s+|\"|\')"
local regex_patterns = {
    prefix .. "systemctl\\s+(?:stop|disable)(\\s+audi(?:t|sp)d(\\.service)?){1,2}" .. suffix,
    prefix .. "(?:pidof|(p)?kill(all)?)[-\\w\\s]{0,10}(\\s+(?:audi(?:t(d)?|spd)?)|\\s+au(?:report|search)){1,4}" .. suffix,
    prefix .. "audit(ctl)?\\s+-(?:e|d)(\\s+0)?" .. suffix,
    prefix .. "rm(mod)?\\s+(\\/etc\\/)?audit(\\/(?:rules\\.d\\/\\*|audit)\\.rules)?" .. suffix
}

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()

    for _, pattern in ipairs(regex_patterns) do
        local check_pattern = cmd_string:search(pattern)
        
        if check_pattern then
            return check_pattern
        end
    end
end

-- Функция очистки null bytes
local function clean(cmd)
    local cleaned_cmd = string.gsub(cmd, "%z", " ")
    cleaned_cmd = string.gsub(cleaned_cmd, "%s+", " ")
    return string.match(cleaned_cmd, "^%s*(.-)%s*$") or cleaned_cmd
end

function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    local command_executed = logline:gets("initiator.command.executed")
    
    if event_type == "EXECVE" or event_type == "PROCTITLE" then
		local auditd_stopping = analyze(command_executed)
		if auditd_stopping then
			grouper1:feed(logline)
		end
	else
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
        
        if log_exec and log_sys then
           local command_executed = log_exec:gets("initiator.command.executed")
           local executed_path = log_sys:gets("initiator.process.path.full")
           local initiator_name = log_sys:gets("initiator.user.name")
           local host_ip = log_exec:get_asset_data("observer.host.ip")
           local host_name = log_exec:get_asset_data("observer.host.hostname")
           local host_fqdn = log_exec:get_asset_data("observer.host.fqdn") 
                
-- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command=command_executed,
                    command_path=executed_path
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
                logs = events,
                mitre = {"T1562", "T1070"},
                trim_logs = 10
                }
            )
            grouper1:clear()
        end    
    end    
end

-- Группер
grouper1 = grouper.new({"observer.host.ip", "observer.host.hostname", "observer.event.id"}, {"observer.event.type"}, "@timestamp,RFC3339", "1m", on_grouped)