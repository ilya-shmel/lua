whitelist = storage.new("wl_hostnames|Linux: Модификация временной метки доступа файла")

-- Шаблон алерта
local template = [[
	Подозрение на модификацию временной метки доступа файла.

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
local prefix = "(?:^|\\/|\\s+|\"|\')"
local time_patterns = {
        prefix .. "\\btouch\\b(?:\\s+(?:-(?:a|m|t|d|r)(?:\\s+(?:\'[^\']+\'|\"[^\"]+\"|[^\\s]+)|[^\\s]*)|--(?:time|date)(?:=(?:\'[^\']+\'|\"[^\"]+\"|[^\\s]+)|\\s+(?:\'[^\']+\'|\"[^\"]+\"|[^\\s]+))))+(?:\\s+(?:\'[^\']+\'|\"[^\"]+\"|[^\\s]+))+",
        prefix .. "setfattr\\s+([-\\w\\s=\\.]+)+\\s+(\\d{4})(-\\d{2}){2}((?:T|:)\\d{2}){3}\\s+(\\/?[^\\/\\s]+\\/)*[\\w\\-\\.]+",
        prefix .. "debugfs\\s+([-\\w\\s=\\.]+)+(\\/?[^\\/\\s]+\\/?)+\\s+(?:a|m|c|cr)time\\s+\\d+\\s+\\/dev\\/(\\/?[^\\/\\s]+\\/?)+",
        prefix .. "\\w+\\s+\\/proc\\/sys\\/vm\\/drop_caches\\s+stat\\s+(\\/?[^\\/\\s]+\\/?)+",
        prefix .. "\\bdd\\b\\s+if=file\\s+of=[\\/\\w-]+\\s+bs=[\\w]{1,5}(\\s+count=\\d+)?",
        prefix .. "\\bcp\\b\\s+-p[-\\s\\/\\w]+"          
}
-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()
    
    for _, pattern in pairs(time_patterns) do
            local regular = cmd_string:search(pattern)
            
            if regular then
                return regular
            end
    end
end

-- Функция работы с логлайном
function on_logline(logline)
    if logline:gets("observer.event.type") == "EXECVE" or logline:gets("observer.event.type") == "PROCTITLE" then
		local search_log_cleaner = analyze(logline:gets("initiator.command.executed"))
        if search_log_cleaner then
            grouper1:feed(logline)
		end
    else
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local log_sys = nil
    local log_exec = nil

    for _, event in ipairs(events) do
        if event:gets("observer.event.type") == "SYSCALL" then
            log_sys = event
        else
            log_exec = event
        end
    end

-- Проверяем, что в группере находятся как события EXECVE/PROCTITLE, так и SYSCALL        
    if log_sys and log_exec then
        local host_name = log_exec:gets("observer.host.hostname")
        if whitelist:get(host_name, "hostname") == nil then                
            local host_ip = log_exec:gets("observer.host.ip")
            local host_fqdn = log_exec:gets("observer.host.fqdn")
            local initiator_name = log_sys:gets("initiator.user.name")
            local path_name = log_sys:gets("initiator.process.path.full")
            local command_executed = log_exec:gets("initiator.command.executed")
            
            if #command_executed > 128 then
                command_executed = command_executed:sub(1,128)
            end
            -- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command=command_executed,
                    command_path=path_name
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
                logs = grouped.aggregatedData.loglines,
                mitre = {"T1070.006"},
                trim_logs = 10
                }
            )
            grouper1:clear()      
        end
    end    
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)