-- Шаблон алерта
local template = [[
	Подозрение на разблокирование учетной записи и вход под ней в течение 5 минут.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор разблокировки): {{ .Meta.initiator_name }}
    Команда разблокирования: {{ .Meta.command }}
    Пользователь (целевой): {{ .Meta.target_name}}
    Путь исполнения: {{ .Meta.login_path }} 
]]

-- Переменные для групперов
local detection_window = "5m"
local grouped_time_field = "@timestamp,RFC3339"
local grouped_by1 = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}
local grouped_by2 = {"target.user.name"}
local aggregated_by1 = {"observer.event.type"}
local aggregated_by2 ={"observer.event.type"}

-- Массив с регулярными выражениями
local pattern = "(?:^|\\/|\\s+|\"|\')(?:passwd|usermod)\\s+-{1,2}u(nlock)?\\s+\\w+(?:$|\\/|\\s+|\"|\')"
local bins = "(?:^|\\/|\\s+|\"|\')(?:passwd|usermod)(?:$|\\/|\\s+|\"|\')(?:$|\\/|\\s+|\"|\')"

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze_command(cmd)
    local cmd_string = cmd:lower()
    local checking_result = cmd_string:search(pattern)
    
    if checking_result then
        return checking_result
    end
end

-- Проверка path name
local function analyze_syscall(path)
    local sys_path = path:lower()
    local checking_path = sys_path:search(bins)
    
    if checking_path then
       return checking_path
    end
end

-- Функция очистки null bytes
local function clean(cmd)
    local cleaned_cmd = string.gsub(cmd, "%z", " ")
    cleaned_cmd = string.gsub(cleaned_cmd, "%s+", " ")
    return string.match(cleaned_cmd, "^%s*(.-)%s*$") or cleaned_cmd
end

-- Функция очистки извлечения имени пользователя
local function extract_username(cmd)
    username = cmd:match("%w+$")
    return username
end


-- Функция работы с логлайном
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    local command_executed = logline:gets("initiator.command.executed")
    local path_name = logline:gets("initiator.process.path.name")
    local syscall_name = logline:gets("target.syscall.name")
    local result_name = logline:gets("event.result.name")

    if event_type == "EXECVE" then
        local is_unblocking = analyze_command(command_executed)
        
        if is_unblocking then
            grouper1:feed(logline)
	    end     
-- Проверяем SYSCALL - нужен только execve и c интересующим нас именем исполняемого файла    
    elseif event_type == "SYSCALL" then
        local syscall_filter = analyze_syscall(path_name)
        if syscall_filter then
            grouper1:feed(logline)        
        end
    elseif event_type == "USER_AUTH" then
        grouper1:feed(logline)
    elseif event_type == "USER_ACCT" then
        grouper1:feed(logline)
    elseif event_type == "USER_START" then
        grouper1:feed(logline)
    end
end

-- Функция сработки группера #1
function on_grouped1(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_sys = nil
    local log_exec = nil
    local log_auth = nil
    local log_acct = nil
    local log_start = nil

    if  unique_events > 2 then
        for _, event in ipairs(events) do
            local event_type = event:gets("observer.event.type")
            if event_type == "SYSCALL" then
                log_sys = event
            elseif event_type == "EXECVE" then
                log_exec = event
            elseif event_type == "USER_AUTH" then
                log_auth = event
            elseif event_type == "USER_ACCT" then
                log_acct = event    
            elseif event_type == "USER_START" then
                log_start = event
            end
        end

        if log_sys and log_exec and log_auth and log_acct and log_start then
            local current_command = log_exec:gets("initiator.command.executed")
            target_user = extract_username(current_command)
            set_field_value(log_exec,"target.user.name", target_user)
            set_field_value(log_sys,"target.user.name", target_user)
            grouper2:feed(log_exec)
            grouper2:feed(log_sys)
            grouper2:feed(log_auth)
            grouper2:feed(log_acct)
            grouper2:feed(log_start)
            grouper1:clear()
        end
    end
end

-- Функция сработки группера #2
function on_grouped2(grouped)
    local events = grouped.aggregatedData.loglines
    
    for _, event in ipairs(events) do
        local event_type = event:gets("observer.event.type")

        if event_type == "EXECVE" then
            unblocked_username = event:gets("target.user.name")
            initiator_path = event:gets("initiator.user.name")
            unblocking_command = event:gets("initiator.command.executed")  
        elseif event_type == "USER_START" then
            target_username = event:gets("target.user.name")
            initiator_path = event:gets("initiator.process.path.full")
            initiator_username = event:gets("initiator.user.name")
        end

        if unblocked_username == target_username then
            local host_name = events[1]:gets("observer.host.hostname")
            local host_ip = events[1]:gets("observer.host.ip")
            local host_fqdn = events[1]:gets("observer.host.fqdn")     
-- Функция алерта
            alert({
                template = template,
                meta = {
                    initiator_name = initiator_username,
                    target_name = target_username,
                    command = unblocking_command,
                    login_path = initiator_path
                    },
                risk_level = 7, 
                asset_ip = host_ip,
                asset_hostname = host_name,
                asset_fqdn = host_fqdn,
                asset_mac = "",
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                logs = grouped.aggregatedData.loglines,
                mitre = {"T1078"},
                trim_logs = 10
                }
            )
            grouper2:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by1, aggregated_by1, grouped_time_field, detection_window, on_grouped1)
grouper2 = grouper.new(grouped_by2, aggregated_by2, grouped_time_field, detection_window, on_grouped2)