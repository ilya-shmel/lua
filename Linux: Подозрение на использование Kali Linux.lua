whitelist = storage.new("wl_hostnames|Linux: Подозрение на использование Kali Linux")
blacklist = storage.new("bl_soft|Linux: Подозрение на использование Kali Linux")

-- Шаблон алерта
local template = [[
	Подозрение на использование дистрибутива Kali Linux.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Выполнена команда: {{ .Meta.command }}
    Окружение, из которого выполнена команда: {{ .Meta.command_path }}
]]

-- Переменные для групера
local detection_window1 = "5m"
local detection_window2 = "3m"
local grouped_by1 = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}
local grouped_by2 = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by1 = {"observer.event.type"}
local aggregated_by2 = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"
local kali_exec_treshold = 5

log_sys_grouper2 = {}
log_exec_grouper2 = {}


local path_pattern = "(?:\\/usr\\/share\\/|https?\\.)?kali(?:-menu|-rolling|\\.org)"
local kali_pattern = "(?:kali\\.org|kali\\.download|kali-linux\\.io|192\\.99\\.200\\.113|kali\\.docker|kalilinux\\.com)"


-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd, pattern)
    local cmd_string = cmd:lower()
    local is_regular = cmd_string:search(pattern)
    local is_command = nil
    
    if is_regular then
        return is_regular
    end
end

-- Функция алерта
local function alert_function(cmd,user,path,ip,hostname,fqdn,events)
    alert({
            template = template,
            meta = {
                user_name=user,
                command=cmd,
                command_path=path
                },
            risk_level = 7.0, 
            asset_ip = ip,
            asset_hostname = hostname,
            asset_fqdn = fqdn,
            asset_mac = "",
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "",
            logs = events,
            mitre = {"T1608"},
            trim_logs = 10
            }
        )
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    local syscall_name = logline:gets("target.syscall.name")
    local host_name = logline:gets("observer.host.name")
    local is_pentester = whitelist:get(host_name)
    
    if is_pentester then
        return
    end
    
    if event_type == "EXECVE" then
		local command_executed = logline:gets("initiator.command.executed")
        local is_kali = analyze(command_executed, kali_pattern)

        if is_kali then
			grouper1:feed(logline)
        end

        grouper2:feed(logline)

    elseif event_type == "SYSCALL" and syscall_name == "execve" then
        local path_name = logline:gets("initiator.process.path.full")
        local application_name = path_name:match("([^/]+)$")
        local is_application = blacklist:get(application_name, "softname")

        if is_application then
            grouper1:feed(logline)
            grouper2:feed(logline)
        end
    
    elseif syscall_name == "openat" or syscall_name == "mount" or syscall_name == "fchmod" then
        grouper1:feed(logline)
    elseif event_type == "PATH" then
        local target_path = logline:gets("target.object.path.full")
        local is_kali_path = analyze(target_path, path_pattern)

        if is_kali_path then
            grouper1:feed(logline)
        end
    elseif event_type == "USER_START" or event_type == "USER_LOGIN" or event_type == "USER_AUTH" then
        grouper1:feed(logline)
	end
    
end

-- Функция сработки группера #1
function on_grouped1(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec = nil
    local log_sys_exe = nil
    local log_sys_path = nil
    local log_path = nil
    local log_user_start = nil
    local log_user_login = nil
    local log_user_auth = nil
    local login_events = {}
    
    if unique_events > 1 then
        for _, event in ipairs(events) do
            local type_event = event:gets("observer.event.type")
            local syscall_name = event:gets("target.syscall.name")
            
            if type_event == "SYSCALL" and syscall_name == "execve" then
                log_sys_exe = event
            elseif type_event == "SYSCALL" then
                log_sys_path = event
            elseif type_event == "PATH" then
                log_path = event
            elseif type_event == "EXECVE" then
                log_exec = event
            elseif type_event == "USER_LOGIN" then
                log_user_login = event
                table.insert(login_events, log_user_login)
            elseif type_event == "USER_AUTH" then
                log_user_auth = event
                table.insert(login_events, log_user_auth)
            elseif type_event == "USER_START" then
                log_user_start = event
                table.insert(login_events, log_user_start)
            end
        end

-- Проверяем выполнение команд от имени пользователя kali
        if log_sys_exe and log_exec then
            local initiator_name = log_sys_exe:gets("initiator.user.name")
            local path_full = log_sys_exe:gets("initiator.process.path.full")
            local kali_exec_events = {}
       
            if initiator_name == "kali" then
                local process_name = log_sys_exe:gets("initiator.process.path.name")
                local command_executed = log_exec:gets("initiator.command.executed")
                local host_ip = log_exec:gets("observer.host.ip")
                local host_hostname = log_exec:gets("observer.host.hostname")
                local host_fqdn = log_exec:gets("observer.host.fqdn", host_hostname)

                table.insert(kali_exec_events, log_exec)
                table.insert(kali_exec_events, log_sys_exe)

                alert_function(command_executed, initiator_name, path_full, host_ip, host_hostname, host_fqdn, kali_exec_events)
                grouper1:clear()
            end
        end
-- Проверяем обращение к специфическим для Kali директориям
        if log_path and log_sys_path then
            local initiator_name = log_sys_path:gets("initiator.user.name")
            local path_full = log_sys_path:gets("initiator.process.path.full")
            local process_name = log_sys_path:gets("initiator.process.path.name")
            local host_ip = log_exec:gets("observer.host.ip")
            local host_hostname = log_exec:gets("observer.host.hostname")
            local host_fqdn = log_exec:gets("observer.host.fqdn", host_hostname)
            local file_name = log_path:gets("target.object.path.full")
            local kali_path_events = {}
            local command_executed = process_name.. " " ..file_name
            table.insert(kali_path_events, log_path)
            table.insert(kali_path_events, log_sys_path)
            
            alert_function(command_executed, initiator_name, path_full, host_ip, host_hostname, host_fqdn, kali_path_events)    
            grouper1:clear()
        end

        if log_user_login and log_user_auth and log_user_start then
            local command_executed = log_user_auth:gets("initiator.shell.name") 
            local initiator_name = log_user_start:gets("initiator.user.name")
            local path_full = log_user_start:gets("initiator.process.path.full")
            local shell_name = log_user_start:gets("initiator.shell.name")
            local host_ip = log_user_start:gets("observer.host.ip")
            local host_hostname = log_user_start:gets("observer.host.hostname")
            local host_fqdn = log_user_start:gets("observer.host.fqdn", host_hostname) 

            if command_executed == "?" then
                local command_executed = log_user_login:gets("initiator.shell.name")
            end
            
            alert_function(command_executed, initiator_name, path_full, host_ip, host_hostname, host_fqdn, login_events)
            grouper1:clear()    
        end
    end
end

-- Функция сработки группера #2
function on_grouped2(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    
    if unique_events > 1 then
        for _, event in ipairs(events) do
            local type_event = event:gets("observer.event.type")

            if type_event == "EXECVE" then
                table.insert(log_exec_grouper2, event)
            else
                table.insert(log_sys_grouper2, event)
            end
        end

        if  #log_exec_grouper2 > kali_exec_treshold then
            
            local host_ip = log_exec_grouper2[1]:gets("observer.host.ip")
            local host_hostname = log_exec_grouper2[1]:gets("observer.host.hostname")
            local host_fqdn = log_exec_grouper2[1]:gets("observer.host.fqdn", host_hostname) 
            
            local commands = ""
            local paths = ""
            local users = {}
            local initiator_name = nil

            for _, event in ipairs(log_exec_grouper2) do
                local current_command = event:gets("initiator.command.executed")
                
                if commands == "" then
                    commands = current_command
                else
                    commands = commands.. "; " ..current_command
                end
            end

            for _, event in ipairs(log_sys_grouper2) do
                local process_name = event:gets("initiator.process.path.name")
                local user_name = event:gets("initiator.user.name")
                
                if paths == "" then
                    paths = process_name
                else
                    paths = paths.. "; " ..process_name
                end
                table.insert(users, user_name)
            end
            
            if #commands > 512 then
	            commands = commands:sub(1,512).. "... "
            end

            initiator_name = users[1]
            
            for _, user in ipairs(users) do
                if user == users[1] then 
                   initiator_name = initiator_name
                else
                   initiator_name = initiator_name.. "; " ..user
                end
            end
            
            alert_function(commands, initiator_name, paths, host_ip, host_hostname, host_fqdn, events)
            grouper2:clear()
            
            log_sys_grouper2 = {}
            log_exec_grouper2 = {}
        end       
    end
end

-- Группер
grouper1 = grouper.new(grouped_by1, aggregated_by1, grouped_time_field, detection_window1, on_grouped1)
grouper2 = grouper.new(grouped_by2, aggregated_by2, grouped_time_field, detection_window2, on_grouped2)