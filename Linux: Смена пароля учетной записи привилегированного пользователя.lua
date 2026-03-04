blacklist = storage.new("privileged_users|Linux: Смена пароля учетной записи привилегированного пользователя")

-- Шаблон алерта
local template = [[
	Обнаружена смена пароля учетной записи привилегированного пользователя.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Пользователь (целевой): {{ .Meta.target_name }}
    Путь к команде: {{ .Meta.command_path }}
]]

-- Переменные для групера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "target.object.name"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Массив с регулярными выражениями
local app_pattern = "\\/usr\\/s?bin\\/((?:g|ch|smb|ldap|k)?passwd|usermod|chage|vi(?:pw|gr)|pw(un)conv|ldap(?:modify|add)|kadmin(\\.local))"

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(text,pattern)
    local text = text:lower()
    local regular = text:search(pattern)
    
    if regular then
        return regular
    end
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    local result_name = logline:gets("event.result.name")
    local path_name = logline:gets("initiator.process.path.full")
    local target_user = logline:gets("target.object.name")
    local user_check = blacklist:get(target_user, "username")

    if event_type == "USER_CHAUTHTOK" and user_check then
		path_check = analyze(path_name, app_pattern)

        if path_check and result_name == "success" then
            grouper1:feed(logline)
        end    
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local log_user_ch = ""
        
    for _, event in ipairs(events) do
        local type_event = event:gets("observer.event.type")
       
        if type_event == "USER_CHAUTHTOK" then
            log_user_ch = event
        end        
    end

-- Проверяем, что в группере находятся как события EXECVE/PROCTITLE, так и SYSCALL
    if (log_user_ch or "") ~= "" then
        local initiator_name = log_user_ch:gets("initiator.user.name")
        local target_name = log_user_ch:gets("target.object.name")
        local host_ip = log_user_ch:gets("observer.host.ip")
        local host_fqdn = log_user_ch:gets("observer.host.fqdn")
        local host_name = log_user_ch:gets("observer.host.hostname")
        local path_name = log_user_ch:gets("initiator.process.path.full")

-- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command_path=path_name,
                    initiator_host=host_name,
                    target_name=target_name
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
                mitre = {"T1098" ,"T1078"},
                trim_logs = 10
                }
            )
            grouper1:clear()     
    end    
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)