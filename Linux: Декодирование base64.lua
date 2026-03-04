whitelist = storage.new("wl_hostnames|Linux: Декодирование base64")

-- Шаблон алерта
local template = [[
	Обнаружено выполнение команды, содержащей декодирование base64.
	На узле: {{ if .First.observer.host.ip }}"{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }} - {{ if .First.observer.host.hostname }}"{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }},
    Пользователем: {{ .Meta.user_name }},
    Была выполнена команда: {{ .Meta.command }},
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}.
]]

-- Переменная с регулярным выражением
local regex_pattern = "(?:^|\\s+|\\/|\"|\')(?i)(?:(?:(?:\\s|^)(?:(?:\\/(?:usr\\/)?bin\\/)?base64\\s+(?:-d|--decode))|(?:openssl\\s+(?:base64\\s+-d|enc\\s+-base64\\s+-d))|(?:python[23]?(?:\\s+.*)?-c[^;]*base64\\.b64decode)|(?:python[23]?\\s+.*base64\\.b64decode)|(?:perl(?:\\s+.*)?-(?:M|e)[^;]*(?:MIME::Base64|decode_base64))|(?:node(?:js)?\\s+.*-e[^;]*(?:Buffer\\.from.*base64|atob))|(?:ruby\\s+.*-e[^;]*base64\\.decode64)|(?:php\\s+.*-r[^;]*base64_decode)|(?:\\/usr\\/bin\\/xxd\\s+-r\\s+-p)|(?:uudecode)|(?:go\\s+run.*encoding\\/base64.*decode)|(?:java\\s+.*Base64\\.(?:getDecoder|decoder))|(?:tr\\s+.*\\|\\s*base64\\s+-d)|(?:(?:sed|awk).*\\|\\s*base64\\s+-d)|(?:base64\\s+-d.*\\|\\s*(?:sh|bash|eval|\\/bin\\/\\w+))|(?:base64\\s+-d.*\\|\\s*base64\\s+-d)|(?:echo\\s+.*\\|\\s*base64\\s+-d)|(?:printf\\s+.*\\|\\s*base64\\s+-d)|(?:b\\s*a\\s*s\\s*e\\s*6\\s*4\\s+.*-d)|(?:base64.*d\\s*e\\s*c\\s*o\\s*d\\s*e)|(?:__import__\\s*\\([^)]*base64[^)]*\\)\\.b64decode)))"

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()
    regular = cmd_string:search(regex_pattern)
    if regular then
       --log(regular)
       return regular
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

        if whitelist:get(log_sys:gets("observer.host.hostname").."_"..log_sys:gets("initiator.user.name"), "username") == nil then
        
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
                    mitre = {"T1140", "T1059", "T1027"},
                    trim_logs = 20
                    }
                )
                grouper1:clear()
            end        
        end    
    end    
end

-- Группер
grouper1 = grouper.new({"observer.host.ip", "observer.host.hostname", "observer.event.id"}, {"observer.event.type"}, "@timestamp,RFC3339", "1m", on_grouped)