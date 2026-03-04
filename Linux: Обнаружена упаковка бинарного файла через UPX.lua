-- Шаблон алерта
local template = [[
	Обнаружена упаковка бинарного файла через UPX.
	На узле: {{ if .First.observer.host.ip }}"{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }} - {{ if .First.observer.host.hostname }}"{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }},
    Пользователем: {{ .Meta.user_name }},
    Была выполнена команда: {{ .Meta.command }},
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}.
]]

-- Массив с регулярными выражениями
local regex_patterns = {
    "(?:^|\\s+|\\/|\"|\')cp\\s+.*upx(.*)?\\s+\\S{3,255}",
    "(?:^|\\s+|\\/|\"|\')upx\\s+(-{1,2}\\d\\s+)?(-{1,2}[a-z-]\\s+)?(((\\s[^\\s ]*)+\\s?)?[[:word:]-]+(\\.\\w{1,5})?(\\s+|$)){1,10}",
    "(?:^|\\s+|\\/|\"|\')cp(\\s+[\\w-]+)?\\s+(((\\/[^\\/ ]*)+\\/?)?[[:word:]-]+(\\.\\w{1,5})?(\\s+)){1,2}[&|]{2}\\s+upx\\s+-o\\s+(((\\/[^\\/ ]*)+\\/?)?[[:word:]-]+(\\.\\w{1,5})?(\\s+|$)){1,2}",
    "(?:^|\\s+|\\/|\"|\')[a-z]+\\s+(\\.\\s+)?((-{1,2}\\w+(\\s+\\w+)?(\\s+)?)){1,10}\\|\\s+xargs\\s+(-{1,2}\\w+\\s+){1,10}upx\\s+-\\d",
    "(?:^|\\s+|\\/|\"|\')xargs\\s+(-{1,2}\\w+\\s+){1,10}upx\\s+-\\d",
    "(?:^|\\s+|\\/|\"|\')for\\s+\\w+\\s+in\\s(\\w+|(\\.)?(\\/[^\\/ ]*)+\\/?)\\*;\\s+do\\s+cp\\s+[[:graph:]]+\\s+[&\\|]{2}\\s+upx\\s+-\\d\\s+[[:graph:]]+;\\s+done"
}
-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()

    for i, pattern in pairs(regex_patterns) do
        regular = cmd_string:search(pattern)
        --log(cmd_string)
        if regular then
            --log(regular)
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
            log(log_ov_events)       
            
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
                mitre = {"T1027.002"},
                trim_logs = 10
                }
            )
            grouper1:clear()
        end
    end    
end

-- Группер
grouper1 = grouper.new({"observer.host.ip", "observer.host.hostname", "observer.event.id"}, {"observer.event.type"}, "@timestamp,RFC3339", "1m", on_grouped)