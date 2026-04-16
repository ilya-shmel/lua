-- Шаблон алерта
local template = [[
	Подозрение на запуск скрипта linenum.

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
local command_pattern = "(?:^|\\/|\\s+|\"|\')(?:\\s+|\\.\\/|\\/)?line(num)?\\.sh(\\s+(-(?:s|t|h))|(-(?:k|r|e)\\s+(\\S+)))?($:^|\\/|\\s+|\"|\')"

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()
    local pattern_checker = cmd_string:search(command_pattern)
    if pattern_checker then
        return pattern_checker
    end
end

-- Функция работы с логлайном
function on_logline(logline)
    if logline:gets("observer.event.type") == "EXECVE" or logline:gets("observer.event.type") == "PROCTITLE" then
		local search_linenum = analyze(logline:gets("initiator.command.executed"))
        if search_linenum then
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
    local log_sys = nil
    local log_exec = nil

    if unique_events > 1 then
        for _, event in ipairs(events) do
            if event:gets("observer.event.type") == "SYSCALL" then
                log_sys = event
            else
                log_exec = event
            end
        end

-- Проверяем, что в группере находятся как события EXECVE/PROCTITLE, так и SYSCALL        
        if log_sys and log_exec then
            local initiator_name = log_sys:gets("initiator.user.name")
            local execution_path = log_sys:gets("initiator.process.path.full")
            local host_ip = log_exec:get_asset_data("observer.host.ip")
            local host_name = log_exec:get_asset_data("observer.host.hostname") 
            local host_fqdn = log_exec:get_asset_data("observer.host.fqdn") 
            local command_executed=log_exec:gets("initiator.command.executed")
            local command_length=command_executed:len().. "..."
            if command_length > 128 then
                command_executed=command_executed:sub(1,128)
            end
            -- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command=command_executed,
                    command_path=execution_path
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
                mitre = {"T1082", "T1059.004"},
                trim_logs = 10
                }
            )
            grouper1:clear()      
        end
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)