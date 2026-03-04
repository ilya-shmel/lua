-- Шаблоны алерта
local template1 = [[
	Подозрение на очистку журналов аудита.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]

local template2 = [[
	Подозрение на перезапись журналов аудита.
	Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Имя файла: {{ .Meta.file_path }}
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
local log_name = "(?:\\/var\\/(?:log|lib)|(?:~|[\\/\\w\\-_]+\\/home|\\/root)\\/\\.(?:local\\/share|cache|config)|\\/(?:opt|srv)[\\/\\w\\-_\\*]+\\/log(s))(\\/[\\/\\w\\-_\\*]+(\\.log)?)?"
local file_pattern = "(?:[-\\w]+\\.log|apt|audit\\.log|(?:b|w)tmp|(?:fail|last|sys)log|installer|journal|private|runit|secure|sssd)((\\.\\d+(\\.\\wz)?))?"
local log_cleaner_patterns = {
        "(?:^|\\/|\\s+|\"|\')rm\\s+([-\\w\\s=]+)+" .. log_name,
        "(?:^|\\/|\\s+|\"|\')truncate\\s+([-a-z\\d\\s=]+)+" .. log_name,
        "(?:^|\\/|\\s+|\"|\')unlink\\s+" .. log_name,
        "(?:^|\\/|\\s+|\"|\')find\\s+" .. log_name .. "[\\-\\w\\s+]+-exec\\s+(?:sh|truncate)\\s+[\\-a-z\\d\\s_>\"$]+\\{\\}\\s*(?:;|\\+)?",
        "(?:^|\\/|\\s+|\"|\')cat\\s+\\/dev\\/(?:null|zero)\\s+>\\s+" .. log_name    
}
local bin_pattern = "\\/?r?syslog(-ng)?"

-- Функция алерта
local function alert_function(template,cmd,user,ip,hostname,fqdn,events,tacticts,path,file)
    alert({
            template = template,
            meta = {
                user_name=user,
                command=cmd,
                command_path=path,
                file_path=file
                },
            risk_level = 8.0, 
            asset_ip = ip,
            asset_hostname = hostname,
            asset_fqdn = fqdn,
            asset_mac = "",
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "",
            logs = events,
            mitre = tactics,
            trim_logs = 10
            }
        )
end

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd,analyze_type)
    local cmd_string = cmd:lower()
    
    if analyze_type == "exec" then
        for _, pattern in pairs(log_cleaner_patterns) do
            local is_cleaner = cmd_string:search(pattern)
            if is_cleaner then
                return is_cleaner
            end
        end
    elseif analyze_type == "syscall" then
        local is_eraser = cmd_string:search(bin_pattern)
        if is_eraser then
            return is_eraser
        end
    elseif analyze_type == "path" then
        local is_path = cmd_string:search(log_name)
        if is_path then
            return is_path
        end 
    elseif analyze_type == "file" then
        local is_file = cmd_string:search(file_pattern)
        if is_file then
            return is_file
        end
    end  
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    local syscall_name = logline:gets("target.syscall.name")
    
    if event_type == "EXECVE" or event_type == "PROCTITLE" then
        local command_executed = logline:gets("initiator.command.executed")
		local search_log_cleaner = analyze(command_executed,"exec")
        if search_log_cleaner then
            grouper1:feed(logline)
		end
    elseif event_type == "SYSCALL" and syscall_name == "execve" then
        grouper1:feed(logline)
    end

    if event_type == "SYSCALL" and syscall_name ~= "execve" then
		local path_name = logline:gets("initiator.process.path.name")
        local syscall_id = logline:gets("target.syscall.id")
        local is_syslog_name = analyze(path_name, "syscall")

        if is_syslog_name then
            return
        elseif syscall_id == "257" or syscall_id == "1" or syscall_id == "2" or syscall_id == "76" then
			grouper2:feed(logline)
        end
    elseif event_type == "PATH" then
        local file_path = logline:gets("target.object.path.full")
        local is_path = analyze(file_path, "path")
        local is_filename = analyze(file_path, "file")

        if is_path or is_filename then
            grouper2:feed(logline)
        end
    end
end

-- Функция сработки группера #1
function on_grouped1(grouped)
    local events = grouped.aggregatedData.loglines
    local log_sys = nil
    local log_exec = nil

    for _, event in ipairs(events) do
        local event_type = event:gets("observer.event.type")
        if  event_type == "SYSCALL" then
            log_sys = event
        else
            log_exec = event
        end
    end

-- Проверяем, что в группере находятся как события EXECVE/PROCTITLE, так и SYSCALL        
    if log_sys and log_exec then
        local tactics = {"T1499.001", "T1499"}
        local command_executed = log_exec:gets("initiator.command.executed")
        local initiator_name = log_sys:gets("initiator.user.name")
        local execution_path = log_sys:gets("initiator.process.path.full")
        local host_ip = log_sys:gets("observer.host.ip")
        local host_name = log_sys:gets("observer.host.hostname")
        local host_fqdn = log_sys:gets("observer.host.fqdn") 

        local command_length = command_executed:len()
        if command_length > 128 then
            command_executed = command_executed:sub(1,128).. "..."
        end

        alert_function(template1, command_executed, initiator_name, host_ip, host_name, host_fqdn, events, tactics, execution_path)       
        grouper1:clear()      
    end
end

-- Функция сработки группера #2
function on_grouped2(grouped)
	local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total

    if unique_events > 1 then
		local log_path = nil
        local log_sys = nil
		for _, event in ipairs(events) do
			local event_type = event:gets("observer.event.type")
            if event_type == "SYSCALL" then
				log_sys = event
			else
				log_path = event
            end
		end
        
        if log_sys and log_path then
           local tactics = {"1070.002"}
           local command_executed = log_sys:gets("initiator.process.path.name")
           local execution_path = log_sys:gets("initiator.process.path.full")
           local initiator_name = log_sys:gets("initiator.user.name")
           local file_name = log_path:gets("target.object.path.full")
           local host_ip = log_sys:gets("observer.host.ip")
           local host_name = log_sys:gets("observer.host.hostname")
           local host_fqdn = log_sys:gets("observer.host.fqdn") 
           
           alert_function(template2, command_executed, initiator_name, host_ip, host_name, host_fqdn, events, tactics, execution_path, file_name)
           grouper2:clear()
        end
    end
end

-- Групперы
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped1)
grouper2 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped2)