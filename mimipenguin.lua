-- Шаблон алерта
local template = [[
	Обнаружена попытка извлечения паролей пользователей с помощью скрипта MimiPenguin.sh.
	Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]

log_exec = {}
log_sys = {}

-- Универсальная функция: возвращает true/false если есть проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()
    local regular1 = cmd_string:search("(?:^|\"|\'|\\\\|\\/|\\s+)if=\\/proc\\/\\d{2,6}\\/mem\\s+of=(\\/[^\\/ ]*)+\\/?")
    return regular1
end

function on_logline(logline)
    if logline:gets("observer.event.type") == "EXECVE" then
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
	local events = grouped.aggregatedData.loglines
    
    if grouped.aggregatedData.unique.total > 1 then
        if #events > 100 then
        
		    for _, log in ipairs(grouped.aggregatedData.loglines) do
		    	if log:gets("observer.event.type") == "SYSCALL" then
		    		table.insert(log_sys, log)
		    	else
		    		table.insert(log_exec, log)
		    	end
		    end

            if #log_exec > 100 and #log_sys > 100 then
                local command = log_exec[1]:gets("initiator.command.executed")
                local target_syscall_name = log_sys[1]:gets("target.syscall.name")

-- Функция алерта
                alert({
                    template = template,
                    meta = {
                        user_name=log_sys[1]:gets("initiator.user.name"),
                        header=header,
                        command=command,
                        command_path=log_sys[1]:gets("initiator.process.path.full")
                        },
                    risk_level = 7.0, 
                    asset_ip = log_exec[1]:get_asset_data("observer.host.ip"),
                    asset_hostname = log_exec[1]:get_asset_data("observer.host.hostname"),
                    asset_fqdn = log_exec[1]:get_asset_data("observer.host.fqdn"),
                    asset_mac = log_exec[1]:get_asset_data(""),
                    create_incident = true,
                    incident_group = "",
                    assign_to_customer = false,
                    incident_identifier = "",
                    logs = events,
                    mitre = {"T1003.007"},
                    trim_logs = 10
                    }
                )
                grouper1:clear()
                log_exec = {}
		        log_sys = {}
            end    
        end   
    end    
end

-- Группер
grouper1 = grouper.new({"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}, {"observer.event.type"}, "@timestamp,RFC3339", "3m", on_grouped)