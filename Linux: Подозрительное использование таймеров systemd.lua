-- Шаблон алерта
local template = [[
	Подозрительное использование таймеров systemd.
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
local timer_pattern = "(?:^|\\/|\\s+|\"|\')(?:systemctl\\s+(?:start|enable)\\s+[^\\s\\/]+\\.timer(?:$|\\/|\\s+|\"|\')|systemd-run\\s+(?:-{1,2}[\\w=,\\s]+){0,10}\\*:[\\d\\/]+\\s+(?:\\/?[^\\/ ]*)+\\/?\\s+(?:-{1,2}[\\w=,\\s]+){0,10}(?:(?:[\"\'])[[:print:]]+(?:[\"\'])?(\\s+)?>{1,2}(\\s+)?(?:\\/[^\\/ ]*)+\\/?)?)"

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()
    local regular = cmd_string:search(timer_pattern)
    if regular then
        return regular
    end
end

-- Функция работы с логлайном
function on_logline(logline)
    
    local event_type = logline:gets("observer.event.type")
    local syscall_name = logline:gets("target.syscall.name")
    local path_name = logline:gets("initiator.process.path.name")
    local command_executed = logline:gets("initiator.command.executed")
    
    if event_type == "EXECVE" or event_type == "PROCTITLE" then
		local result = analyze(command_executed)
		if result then
			grouper1:feed(logline)
		end
    else
        grouper1:feed(logline)
    
	end
end

-- Функция сработки группера
function on_grouped(grouped)

    if grouped.aggregatedData.unique.total > 1 then
		local events = grouped.aggregatedData.loglines
        local log_exec = nil
	    local log_sys = nil
		for _, log in ipairs(events) do
			if log:gets("observer.event.type") == "SYSCALL" then
				log_sys = log
			else
				log_exec = log
			end
		end
        
        if log_exec and log_sys then
           local command = log_exec:gets("initiator.command.executed")
-- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name=log_sys:gets("initiator.user.name"),
                    header=header,
                    command=command,
                    command_path=log_sys:gets("initiator.process.path.full")
                    },
                risk_level = 5.0, 
                asset_ip = log_exec:get_asset_data("observer.host.ip"),
                asset_hostname = log_exec:get_asset_data("observer.host.hostname"),
                asset_fqdn = log_exec:get_asset_data("observer.host.fqdn"),
                asset_mac = log_exec:get_asset_data(""),
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                logs = grouped.aggregatedData.loglines,
                mitre = {"T1053.006"},
                trim_logs = 10
                }
            )
            grouper1:clear()
        end    
    end    
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)