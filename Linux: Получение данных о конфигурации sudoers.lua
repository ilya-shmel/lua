-- Шаблон алерта
local template = [[
	Подозрение на получение данных о конфигурации sudoers.

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
local suffix = "(?:$|\\/|\\s+|\"|\')"
local opts = "[-\"*$\\/\\w(%\\s~\\.]+"
local command_pattern = {
    prefix .. "find\\s+[\\/\\w\\s]+-(?:name|samefile|inum|path|wholename)\\s+" .. opts .. "sudo" .. opts .. suffix,
    prefix .. "(?:cat|ls|stat|getfattr|namei|hexdump|xxd|strings|visudo)\\s+([-\\w\\s%]){0,10}\\/(?:etc|var\\/db|usr\\/bin)\\/sudo(ers)?(\\.d)?" .. suffix,
    prefix .."grep\\s+-\\w+\\s+(?:\"|\')?(vi)?sudo(ers)?[\\~\\/\\|\\w\\s\\.]+"
}

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()
    
    for _, pattern in ipairs(command_pattern) do
        local pattern_checker = cmd_string:search(pattern)
        
        if pattern_checker then
            return pattern_checker
        end
    end
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    
    if event_type == "EXECVE" or event_type == "PROCTITLE" then
		local command_executed = logline:gets("initiator.command.executed")
        local search_sudo = analyze(command_executed)
        if search_sudo then
            grouper1:feed(logline)
		end
    elseif event_type == "SYSCALL" then
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_sys, log_exec
    
    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_type = event:gets("observer.event.type")
            if event_type == "SYSCALL" then
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
                risk_level = 9.0, 
                asset_ip = host_ip,
                asset_hostname = host_name,
                asset_fqdn = host_fqdn,
                asset_mac = "",
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                logs = grouped.aggregatedData.loglines,
                mitre = {"T1069", "T1548"},
                trim_logs = 10
                }
            )
            grouper1:clear()  
        end
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)