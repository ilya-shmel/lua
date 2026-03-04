whitelist = storage.new("wl_hostnames|Linux: Сбор информации о сетевых соединениях при помощи ss и netstat")

-- Шаблон алерта
local template = [[
	Был выполнен сбор информации о сетевых соединениях.

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
local command_pattern = "(?:^|\\/|\\s+|\"|\')(?:netstat|ss)(\\s+-{1,2}[\\w:=\\s\\'\\(\\)@]+)?(?:$|\\/|\\s+|\"|\')"

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd,pattern)
    local cmd_string = cmd:lower()
    local regular = cmd_string:search(pattern)
            
    if regular then
        return regular
    end
end

-- Функция работы с логлайном
function on_logline(logline)
    if logline:gets("observer.event.type") == "EXECVE" or logline:gets("observer.event.type") == "PROCTITLE" then
		local net_marker = analyze(logline:gets("initiator.command.executed"),command_pattern)
        if net_marker then
            grouper1:feed(logline)
		end
    else
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local log_sys = ""
    local log_exec = ""

    for _, event in ipairs(events) do
        if event:gets("observer.event.type") == "SYSCALL" then
            log_sys = event
        else
            log_exec = event
        end
    end

    local user_name = log_sys:gets("initiator.user.name")
    
    if whitelist:get(host_name, "hostname") == nil then

-- Проверяем, что в группере находятся как события EXECVE/PROCTITLE, так и SYSCALL        
        if log_sys ~= "" and log_exec ~= "" then
            local host_ip = log_exec:gets("observer.host.ip")
            local host_fqdn = log_exec:gets("observer.host.fqdn")
            local host_name = log_exec:gets("observer.host.hostname")
            local initiator_name = log_sys:gets("initiator.user.name")
            local path_name = log_sys:gets("initiator.process.path.full")
            local command_executed = log_exec:gets("initiator.command.executed")
            
            if command_executed and #command_executed > 128 then
                command_executed = command_executed:sub(1,128)
            end
            -- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command_path=path_name,
                    command=command_executed
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
                command=command_executed,
                logs = grouped.aggregatedData.loglines,
                mitre = {"T1049", "T1082"},
                trim_logs = 10
                }
            )
            grouper1:clear()      
        end
    end    
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)