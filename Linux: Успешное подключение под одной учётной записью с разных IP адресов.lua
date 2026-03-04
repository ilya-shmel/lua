whitelist = storage.new("mass_hosts|Linux: Успешное подключение под одной учётной записью с разных IP-адресов")

-- Шаблон алерта
local template = [[
	Обнаружено успешное подключение под одной учётной записью с разных узлов.

    Пользователь(инициатор): {{ .Meta.user_initiator }}
    Пользователь(целевой): {{ .Meta.user_target}}
    Окружение, из которого выполнен вход: {{ .Meta.command_path }}
    Узел, с которого выполнен вход: 
    IP - "{{ .Meta.initiator_address }}"
    Hostname - "{{ .Meta.initiator_host }}"

    Узлы, на которых осуществлено подключение: {{ .Meta.hosts_initiators }}
]]

-- Переменные для групера
local detection_window1 = "1m"
local detection_window2 = "5m"
local grouped_by1 = {"observer.host.ip", "observer.host.hostname", "initiator.host.hostname"}
local grouped_by2 = {"target.user.name"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"
local hosts_treshold = 1

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
      
    if  event_type == "USER_AUTH" or event_type == "USER_ACCT" or event_type == "USER_START" then
		grouper1:feed(logline)
    end
end

-- Функция сработки группера #1
function on_grouped1(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_auth, log_acct, log_start

    if unique_events > 1 then 
        for _, event in ipairs(events) do
            local event_type = event:gets("observer.event.type")
                        
            if event_type == "USER_AUTH" then
                log_auth = event 
            elseif event_type == "USER_ACCT" then
                log_acct = event
            elseif event_type == "USER_START" then
                log_start = event    
            end        
        end
   
-- Отправляем события во второй группер
        if log_auth and log_acct and log_start then
            local user_auth = log_auth:gets("target.user.name")
            local user_acct = log_acct:gets("target.user.name")
            local user_start = log_start:gets("target.user.name")

            if user_acct == user_auth and user_start == user_auth then
               local host = log_start:gets("initiator.host.hostname") 
               grouper2:feed(log_start)
               grouper1:clear()
            end
        end
    end
end        

-- Функция сработки группера #2
function on_grouped2(grouped)
    local events = grouped.aggregatedData.loglines
    local initiator_hosts = {}
    local initiator_users = {}
    local initiator_ips = {}
    local initiator_hosts_list = {}

    if #events > 1 then
        for _, event in ipairs(events) do
            local event_type = event:gets("observer.event.type")
            local target_user = event:gets("target.user.name")
            local initiator_ip = event:gets("initiator.host.ip")
            local target_ip = event:gets("observer.host.ip")
            local connection_info = initiator_ip.. "_" ..target_ip.. "_" ..target_user 
            local host_check = whitelist:get(connection_info, "connection_data")

            if host_check == nil or host_check == false then
                table.insert(initiator_hosts, event:gets("initiator.host.hostname"))
                table.insert(initiator_ips, event:gets("initiator.host.ip"))
                table.insert(initiator_users, event:gets("initiator.user.name"))
            end    
        end

        unique_hosts = check_hosts(initiator_hosts)
        is_same_user = check_users(initiator_users)

        if #initiator_hosts > hosts_treshold and unique_hosts and is_same_user then
                
            local initiator_username = events[1]:gets("initiator.user.name")
            local target_username = events[1]:gets("target.user.name")
            local path_name = events[1]:gets("initiator.process.path.full")
            local target_hostname = events[1]:gets("target.host.hostname")
            local initiator_hostname = events[1]:gets("initiator.host.hostname")
            local target_ip = events[1]:gets("target.host.ip")
            local initiator_ip = events[1]:gets("initiator.host.ip")
            local host_ip = events[1]:gets("observer.host.ip")
            local host_fqdn = events[1]:gets("observer.host.fqdn")
            local host_name = events[1]:gets("observer.host.hostname")
            
            for index = 1, #initiator_hosts do
                initiator_hosts_list[index] = "Hostname: " .. initiator_hosts[index] .. " - IP: " .. initiator_ips[index] 
            end
       
            local all_initiator_hosts = table.concat(initiator_hosts_list, "; ")
-- Функция алерта
            alert({
                template = template,
                meta = {
                    user_initiator=initiator_username,
                    user_target=target_username,
                    command_path=path_name,
                    target_host=target_hostname,
                    target_address=target_ip,
                    initiator_host=initiator_hostname,
                    initiator_address=initiator_ip,
                    hosts_initiators=all_initiator_hosts
                    },
                risk_level = 7.0, 
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
       
-- Групперы
grouper1 = grouper.new(grouped_by1, aggregated_by, grouped_time_field, detection_window1, on_grouped1)
grouper2 = grouper.new(grouped_by2, aggregated_by, grouped_time_field, detection_window2, on_grouped2)