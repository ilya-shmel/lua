-- Шаблон алерта
local template = [[
	Обнаружено копирование исполнимого файла под именем crond с целью запуска и маскировки под легитимный процесс crond..
	Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]

local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local detection_window = "1m"
local grouped_time_field = "@timestamp,RFC3339"

-- Массив с регулярными выражениями
local prefix = "(?:^|\\s+|\\/|\"|\')"
local regex_patterns = {
    prefix .."cp\\s+(-{1,2}[\\w=\\,]+\\s+)?(\\/[^\\/ ]*)+\\/?\\s+(\\/[^\\/ ]*)+crond",
    prefix .."install\\s+((-{1,2}[\\w=\\,\\s]+){1,10})?(\\/[^\\/ ]*)+\\/?\\s+(\\/[^\\/ ]*)+crond",
    prefix .."mv\\s+((-{1,2}[\\w=\\,\\s]+){1,10})?(\\/[^\\/ ]*)+\\/?\\s+(\\/[^\\/ ]*)+crond",
    prefix .."rsync\\s+((-{1,2}[\\w=+\\,\\s]+){1,10})?(\\/[^\\/ ]*)+\\/?\\s+(\\/[^\\/ ]*)+crond",
    prefix .."tar\\s+(-{1,2}c\\s+|--directory(?:=|\\s+))(\\/[^\\/ ]*)+\\s+(-{1,2}[\\w\\,=\\s]+\\s+)-(\\s+crond)?",
    prefix .."dd\\s+(?:if|of)=(\\/[^\\/\\s]*)+\\s+(?:if|of)=(\\/?[^\\/\\s]*)\\/crond?\\s+[\\w=\\s]+",
    prefix .."base64\\s+(\\/[^\\/ ]*)+\\s+>{1,2}\\s+(\\/[^\\/ ]*)+\\/crond",
    prefix .."ln\\s+((?:-s|--symbolic)|(-{1,2}[\\w=\\,\\s]+){1,10})?(\\s+)?((\\/[^\\/ ]*)+\\s+)((\\/[^\\/ ]*)+\\/crond)",
    prefix .."(?:nohup|setsid)?(\\s+)?((\\/[^\\/ ]*)+\\/crond)((\\s+>(\\s+)?(\\/[^\\/ ]*)+\\s+\\d>&\\d)?\\s+&)?"
}
-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()

    for _, pattern in pairs(regex_patterns) do
        regular = cmd_string:search(pattern)
        if regular then
            return regular
        end
    end
end

function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    if event_type == "EXECVE" then
		local command_executed = logline:gets("initiator.command.executed")
        local is_masked = analyze(command_executed)
		if is_masked then
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
                mitre = {"T1036.003","T1547"},
                trim_logs = 10
                }
            )
            grouper1:clear()
        end    
    end    
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)