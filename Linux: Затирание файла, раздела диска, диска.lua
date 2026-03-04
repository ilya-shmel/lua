-- Шаблон алерта
local template = [[
	Обнаружена попытка затирание файла, раздела диска, диска..
	Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]

-- Массив с регулярными выражениями
local prefix = "(?:^|\\/|\\s+|\"|\'|\\\\)" 
local regex_patterns = {
    prefix.. "dd(\\s+(?:if|of)=\\/dev\\/\\w+){2}(\\s+?[\\w=]+)?",
    prefix.. "shred(\\s+-\\w+)+(\\s+\\d)?\\s+(\\/?[^\\/\\s]+\\/)?[^\\/\\s]+",
    prefix.. "(?:fdisk|parted|mkfs|wipefs)(\\.\\w+)?(\\s+-\\w+)?\\s+\\/dev\\/\\w+"
}

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()

    for i, pattern in pairs(regex_patterns) do
        local regular = cmd_string:search(pattern)

        if regular then
            return true
        end
    end

    return false
end

function on_logline(logline)
    if logline:gets("observer.event.type") == "EXECVE" or logline:gets("observer.event.type") == "PROCTITLE" then
		local is_erasing = analyze(logline:gets("initiator.command.executed"))
		if is_erasing then
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
    local log_exec = nil
	local log_sys = nil

    if unique_events > 1 then
		for _, log in ipairs(events) do
			if log:gets("observer.event.type") == "SYSCALL" then
				log_sys = log
			else
				log_exec = log
			end
		end
        
        if log_exec and log_sys then
           local command_executed = log_exec:gets("initiator.command.executed")
           local is_command = analyze(command_executed)        
                
-- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name=log_sys:gets("initiator.user.name"),
                    command=command_executed,
                    command_path=log_sys:gets("initiator.process.path.full")
                    },
                risk_level = 8.0, 
                asset_ip = log_exec:get_asset_data("observer.host.ip"),
                asset_hostname = log_exec:get_asset_data("observer.host.hostname"),
                asset_fqdn = log_exec:get_asset_data("observer.host.fqdn"),
                asset_mac = log_exec:get_asset_data(""),
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                logs = grouped.aggregatedData.loglines,
                mitre = {"T1561.001", "T1561.002"},
                trim_logs = 10
                }
            )
            grouper1:clear()
        end    
    end    
end

-- Группер
grouper1 = grouper.new({"observer.host.ip", "observer.host.hostname", "observer.event.id"}, {"observer.event.type"}, "@timestamp,RFC3339", "1m", on_grouped)