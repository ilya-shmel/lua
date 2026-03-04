-- Шаблон алерта
local template = [[
	Обнаружена утилита для прослушки сетевого трафика.
	Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]

-- Массив с регулярными выражениями
local regex_patterns = {
    "(^|\\s+|\\/|\\\"|\\\')((?:t|wire)shark|nethogs|iftop|nmap|arpspoof|ettercap|urlsnarf|ngrep|tcp(?:flow|trace|dump|ick)|iptraf-ng|dsniff|driftnet|aircrack-ng|mitmproxy|suricata|zeek)((?:|\\.sh|\\.bash|\\.zsh|\\.ksh|\\.pl|\\.py|\\.rb|\\.php|\\.jar|\\.run|\\.bin|\\.appimage|\\.so|\\.plx|\\.tcl|\\.lua|\\.pyc|\\.pyo|\\.war|\\.ear)?\\s+((-{1,2}[\\w=\\,\\s,\\.\'\"]+){1,20}|((\\/[^\\/ ]*)+)(\\s+)?){1,10})?",
    "(bpftrace)\\s+((-{1,2}[\\w=\\,\\s,\\.\'\"]+){1,20})?(\'|\")[\\w:_]+\\s+{(\\s+)?[\\w\"\',;()->\\s%\\]+}(\'|\")"
}

local exclude_pattern = "(?:^|\\s+|\\/|\\\\|\"|\')?(?:ansible|puppet|chef|salt|terraform|docker|podman|fail2ban|ufw|firewalld|systemd|auditd)"

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()

    for i, pattern in pairs(regex_patterns) do
        local regular = cmd_string:search(pattern)
        local exclude_check = cmd_string:search(exclude_pattern)
        if exclude_check == false then
            return regular
        end
    end
end

function on_logline(logline)
    if logline:gets("observer.event.type") == "EXECVE" or logline:gets("observer.event.type") == "PROCTITLE" then
		local result = analyze(logline:gets("initiator.command.executed"))
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
           local is_command = analyze(command)        
                
-- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name=log_sys:gets("initiator.user.name"),
                    header=header,
                    command=command,
                    command_path=log_sys:gets("initiator.process.path.full")
                    },
                risk_level = 7.0, 
                asset_ip = log_exec:get_asset_data("observer.host.ip"),
                asset_hostname = log_exec:get_asset_data("observer.host.hostname"),
                asset_fqdn = log_exec:get_asset_data("observer.host.fqdn"),
                asset_mac = log_exec:get_asset_data(""),
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                logs = grouped.aggregatedData.loglines,
                mitre = {"T1040"},
                trim_logs = 10
                }
            )
            grouper1:clear()
        end    
    end    
end

-- Группер
grouper1 = grouper.new({"observer.host.ip", "observer.host.hostname", "observer.event.id"}, {"observer.event.type"}, "@timestamp,RFC3339", "1m", on_grouped)