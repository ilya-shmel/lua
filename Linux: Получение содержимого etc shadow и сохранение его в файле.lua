-- Шаблон алерта
local template = [[
	Обнаружено получение содержимого /etc/shadow и сохранение его в файле.
	Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]

-- Массив с регулярными выражениями
local regex_patterns = {
    "(?:^|\\s+|\\/|\"|\')cat\\s+(\\/etc\\/)?shadow\\s+>(>)?\\s+(\\/[^\\/ ]*)+",
    "(?:^|\\s+|\\/|\"|\')sed\\s+(?:\"|\'){2}\\s+(\")?(\\/etc\\/)?shadow(\")?\\s+>{1,2}\\s+(\")?(\\/[^\\/ ]*)+\\/?(\")?",
    "(?:^|\\s+|\\/|\"|\')awk\\s+\'{\\w+}\'\\s+(\\/etc\\/)?shadow\\s+>{1,2}\\s+(\\/[^\\/ ]*)+\\/?",
    "(?:^|\\s+|\\/|\"|\')tee\\s+(\\/[^\\/ ]*)+\\/?\\s+<\\s+(\\/etc\\/)?shadow",
    "(?:^|\\s+|\\/|\"|\')cat\\s+(\\/etc\\/)?shadow\\s+\\|\\s+tee\\s+(\\/[^\\/ ]*)+\\/?\\s+>{1,2}(\\/[^\\/ ]*)+\\/?",
    "(?:^|\\s+|\\/|\"|\')dd\\s+if=(\\/etc\\/)?shadow\\s+of=(\\/[^\\/ ]*)+\\/?\\s+(\\w+=\\w+(\\s+)?){1,5}",
    "(?:^|\\s+|\\/|\"|\')rsync\\s+(-{1,2}\\w+(=\\w+)?\\s+){1,10}(\\/etc\\/)?shadow\\s+(\\/[^\\/ ]*)+\\/?",
    "(?:^|\\s+|\\/|\"|\')tar\\s+([-\\w\\s\"$\\(\\)]+(?:(\\/etc\\/shadow)?|shadow)){1,2}",
    "(?:^|\\s+|\\/|\"|\')(?:(n)?vi(m)?|nano|emacs|micro|jed|joe|mcedit|pico)\\s+(\\/etc\\/)?shadow"
}
-- Универсальная функция: возвращает true/false если есть проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()

    for i, pattern in pairs(regex_patterns) do
        regular = cmd_string:search(pattern)
            
        if regular then
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
		local log_exec = ""
		local log_sys = ""
		for _, log in ipairs(grouped.aggregatedData.loglines) do
			if log:gets("observer.event.type") == "SYSCALL" then
				log_sys = log
			else
				log_exec = log
			end
		end
       
        if log_exec ~="" and log_sys ~= "" then
            local command = log_exec:gets("initiator.command.executed")
            local target_syscall_name = log_sys:gets("target.syscall.name")
            local log_ov_events = command .. " <-> " .. target_syscall_name

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
                mitre = {"T1003.008"},
                trim_logs = 10
                }
            )
            grouper1:clear()
        end
    end    
end

-- Группер
grouper1 = grouper.new({"observer.host.ip", "observer.host.hostname", "observer.event.id"}, {"observer.event.type"}, "@timestamp,RFC3339", "1m", on_grouped)