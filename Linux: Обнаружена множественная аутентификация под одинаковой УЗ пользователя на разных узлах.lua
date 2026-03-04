whitelist = storage.new("mass_users|Linux: Обнаружена множественная аутентификация под одинаковой УЗ пользователя на разных узлах")

-- Шаблон алерта
local template = [[
	Обнаружена множественная аутентификация под одинаковой УЗ пользователя на разных узлах.

    Узлы: {{ .Meta.hosts_target }} 
    
    Пользователь(инициатор): {{ .Meta.user_initiator }}
    Пользователь(целевой): {{ .Meta.user_target}}
    Окружение, из которого выполнен вход: {{ .Meta.command_path }}
    Узел, с которого выполнен вход: 
    IP - "{{ .Meta.initiator_address }}"
    Hostname - "{{ .Meta.initiator_host }}"
]]

-- Переменные для групера
local detection_window1 = "1m"
local detection_window2 = "5m"
local grouped_by1 = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}
local grouped_by2 = {"target.user.name"}
local aggregated_by = {"observer.host.hostname"}
local grouped_time_field = "@timestamp,RFC3339"

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(text,pattern)
    local text = text:lower()
    local regular = text:search(pattern)
    
    if regular then
        return regular
    end
end

-- Функция, проверяющая, что в массиве узлов нет повторяющихся элементов 
local function check_hosts(hosts_array)
    local all_target_hosts = {}
    
    for index, host in ipairs(hosts_array) do 
        all_target_hosts[index] = host 
    end
    
    table.sort(all_target_hosts)
    
    for index = 2, #all_target_hosts do
        if all_target_hosts[index] == all_target_hosts[index-1] then 
            return false, all_target_hosts[index] 
        end
    end
    
    return true
end

-- Функция, проверяющая, что в массиве пользователей все элементы равны
local function check_users(users_array)
    local all_target_users = {}
    
    for index, user in ipairs(users_array) do 
        all_target_users[index] = users 
    end
    
    table.sort(all_target_users)
    
    for index = 2, #all_target_users do
        if all_target_users[index] ~= all_target_users[index-1] then 
            return false, all_target_users[index] 
        end
    end
    
    return true
end 


-- Функция работы с логлайном
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    local result_name = logline:gets("event.result.name")
    local initiator_user = logline:gets("initiator.user.name")
        
    if  event_type == "USER_AUTH" or event_type == "USER_ACCT" or event_type == "USER_START" then
		if result_name == "success" and not user_check then
            grouper1:feed(logline)
        end    
    end
end

-- Функция сработки группера #1
function on_grouped1(grouped)
    local events = grouped.aggregatedData.loglines
    local log_auth = nil
    local log_acct = nil
    local log_start = nil

    for _, event in ipairs(events) do
        local event_type = event:gets("observer.event.type")
        
        if event_type == "USER_AUTH" then
            log_auth = event    
        elseif event_type == "USER_ACCT" then
            log_acct = event
        else
            log_start = event    
        end        
    end

-- Отправляем события во второй группер
    if log_auth and log_acct and log_start then
        local user_auth = log_auth:gets("target.user.name")
        local user_acct = log_acct:gets("target.user.name")
        local user_start = log_start:gets("target.user.name")
        
        if user_acct == user_auth and user_start == user_auth then
            grouper2:feed(log_start)
            grouper1:clear()
        end
    end
end        

-- Функция сработки группера #2
function on_grouped2(grouped)
    local events = grouped.aggregatedData.loglines
    local target_hosts = {}
    local target_users = {}
    local target_ips = {}
    local target_hosts_list = {}
    
    for _, event in ipairs(events) do
        table.insert(target_hosts, event:gets("observer.host.hostname"))
        table.insert(target_users, event:gets("target.user.name"))
        table.insert(target_ips, event:gets("observer.host.ip"))
    end

    user_check = whitelist:get(initiator_user, "username")
    unique_hosts = check_hosts(target_hosts)
    is_same_user = check_users(target_users)

    if #target_hosts > 2 and unique_hosts and is_same_user and not user_check then
        local initiator_username = events[1]:gets("initiator.user.name")
        local target_username = events[1]:gets("target.user.name")
        local path_name = events[1]:gets("initiator.process.path.full")
        local initiator_hostname = events[1]:gets("initiator.host.hostname")
        local initiator_ip = events[1]:gets("initiator.host.ip")
        local host_ip = events[1]:gets("observer.host.ip")
        local host_fqdn = events[1]:gets("observer.host.fqdn")
        local host_name = events[1]:gets("observer.host.hostname")

        for index = 1, #target_hosts do
            target_hosts_list[index] = "Hostname: " .. target_hosts[index] .. " - IP: " .. target_ips[index] 
        end

        all_target_hosts = table.concat(target_hosts_list, "; ")
-- Функция алерта
        alert({
            template = template,
            meta = {
                user_initiator=initiator_username,
                user_target=target_username,
                command_path=path_name,
                initiator_host=initiator_hostname,
                initiator_address=initiator_ip,
                hosts_target=all_target_hosts
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
            mitre = {"T1078"},
            trim_logs = 10
            }
        )
        grouper2:clear()
    end
end
       

-- Групперы
grouper1 = grouper.new(grouped_by1, aggregated_by, grouped_time_field, detection_window1, on_grouped1)
grouper2 = grouper.new(grouped_by2, aggregated_by, grouped_time_field, detection_window2, on_grouped2)