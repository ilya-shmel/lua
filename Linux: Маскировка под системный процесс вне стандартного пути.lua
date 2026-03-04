-- Шаблон алерта
local template = [[
	Был выполнен запуск системного процесса из нестандартного пути.
    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]

-- Массив с регулярными выражениями
local path_patterns = {
    "^\\/(?:lib\\/systemd|usr\\/(s)?bin|usr\\/lib)\\/",
    "^\\/(s)?bin\\/",
    "(?:\\/libexec|\\/usr\\/libexec)\\/"
}

-- Переменная с регулярным выражением
local binary_pattern = "^(\\/[^\\/ ]*)+\\/(?:systemd(?:-journald|-udevd)?|NetworkManager|ssh(d)?|(ana)?cron(d)?|rsyslogd|polkitd|udevd|cupsd|sssd|dbus(?:-launch|-daemon)|ntpd|chronyd|auditd|kube(?:-proxy|let))$"

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(path)
    local binary_path = path:lower()
    
    for i, pattern in pairs(path_patterns) do
        regular1 = binary_path:search(pattern)
        if regular1 == false then
            regular2 = binary_path:search(binary_pattern)
            return regular2
        else
            return false
        end
    end
end

function on_logline(logline)
    if logline:gets("observer.event.type") == "SYSCALL" then
        local result = analyze(logline:gets("initiator.process.path.full"))
		if result then
			grouper1:feed(logline)
		end
	else
        if logline:gets("observer.event.type") == "EXECVE" or logline:gets("observer.event.type") == "PROCTITLE" then
            grouper1:feed(logline)
        end
	end
end

-- Функция сработки группера
function on_grouped(grouped)
	if grouped.aggregatedData.unique.total > 1 then
		local log_exec = nil
		local log_sys = nil
		for _, log in ipairs(grouped.aggregatedData.loglines) do
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
                risk_level = 9.0, 
                asset_ip = log_exec:get_asset_data("observer.host.ip"),
                asset_hostname = log_exec:get_asset_data("observer.host.hostname"),
                asset_fqdn = log_exec:get_asset_data("observer.host.fqdn"),
                asset_mac = log_exec:get_asset_data(""),
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                logs = grouped.aggregatedData.loglines,
                mitre = {"T1036.001"},
                trim_logs = 10
                }
            )
            grouper1:clear()
        end    
    end    
end

-- Группер
grouper1 = grouper.new({"observer.host.ip", "observer.host.hostname", "observer.event.id"}, {"observer.event.type"}, "@timestamp,RFC3339", "1m", on_grouped)