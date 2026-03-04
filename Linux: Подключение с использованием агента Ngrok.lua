-- Шаблон алерта

local template = [[
Обнаружено использование Ngrok-туннеля.

Узел:
{{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
{{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}

Пользователь(инициатор): {{ .Meta.user_name }}
Выполненная команда: {{ .Meta.command }}
Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
Тип операции: {{ .Meta.operation_type }}
]]

-- Переменные для групера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Паттерны для ngrok
local ngrok_patterns = {
    "(\\.?\\/)?ngrok\\b\\s+(http|tcp|tls|start|authtoken|config)",
    "(?:n(et)?c(at)?|curl|wget|ssh|telnet)\\s+(-{1,2}[\\s\\w=:\'{}\\.\\|\\/]+\\s+){0,20}(\\w+\\.){1,4}ngrok\\.io",
    "(?:n(et)?c(at)?|curl|wget|ssh|telnet)\\s+(-{1,2}[\\w]+\\s+)+[-\\w\\.:#@]+\\s+[\\w-]+@[-\\w\\.]{0,32}ngrok[-\\w\\.][^:]+\\s+[^\\s:]+:[\\w[:punct:]]+"
}

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()

    for _, pattern in pairs(ngrok_patterns) do
        is_pattern = cmd_string:search(pattern)
        if is_pattern then
            return is_pattern
        end
    end
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
        
    if event_type == "EXECVE" then
		local command_executed = logline:gets("initiator.command.executed")
        local is_ngrok = analyze(command_executed)
		
        if is_ngrok then
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
			elseif event_type == "EXECVE" then
				log_exec = event
			end
		end
        
        if log_exec and log_sys then
           local command_executed = log_exec:gets("initiator.command.executed")
           local initiator_name = log_sys:gets("initiator.user.name")
           local execution_path = log_sys:gets("initiator.process.path.full")
           local host_ip = log_exec:get_asset_data("observer.host.ip")
           local host_name = log_exec:get_asset_data("observer.host.hostname")
           local host_fqdn = log_exec:get_asset_data("observer.host.fqdn")
               
-- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command=command_executed,
                    command_path=execution_path
                    },
                risk_level = 9.5, 
                asset_ip = host_ip,
                asset_hostname = host_name,
                asset_fqdn = host_fqdn,
                asset_mac = "",
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                logs = events,
                mitre = {"T1572", "T1090", "T1071.001", "T1059.004"},
                trim_logs = 10
                }
            )
            grouper1:clear()
        end    
    end    
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)
