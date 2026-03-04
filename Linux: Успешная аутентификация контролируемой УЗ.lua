controlled_users = storage.new("controlled_users|Linux: Успешная аутентификация контролируемой УЗ")

-- Шаблон алерта
local template = [[
	Обнаружена успешная аутентификация контролируемой учетной записи.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name1 }}
    Пользователь(целевой): {{ .Meta.user_name2 }}
    Окружение, из которого выполнен вход: {{ .Meta.command_path }}
    Узел, с которого выполнен вход: 
    IP - "{{ .Meta.initiator_address }}"
    Hostname - "{{ .Meta.initiator_host }}"
]]

-- Переменные для групера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "target.user.name"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Массив с регулярными выражениями
local pattern = "(?:\\/|\'|\")?(?:sshd|su)"

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
    local target_user = logline:gets("target.user.name")
        
    if event_type == "USER_LOGIN" or event_type == "USER_AUTH" or event_type == "CRED_ACQ" or event_type == "USER_START" then
		user_check = controlled_users:get(target_user, "username")
        if user_check and result_name == "success" then
            grouper1:feed(logline)
        end    
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines

-- Отображение type_event -> имя переменной, которую нужно установить
    local mapping = {
      USER_LOGIN = "log_user_login",
      USER_AUTH  = "log_user_auth",
      CRED_ACQ   = "log_cred_acq",
      USER_START = "log_user_start",
    }

    for _, event in ipairs(events) do
        local type_event = event:gets("observer.event.type")
-- Нормализуем тип и назначаем глобальную переменную с нужным именем
        local type = tostring(type_event):upper()
        local varname = mapping[type]
        if varname then
            _G[varname] = event   -- присваиваем глобальную переменную, например: log_user_login = event
        end        
    end

    -- Проверяем, что в группере находятся как события всех типов
    if log_user_login and log_user_auth and log_cred_acq and log_user_start then

        local initiator_username = log_user_start:gets("initiator.user.name")
        local target_username = log_user_start:gets("target.user.name")
        local host_ip = log_user_start:gets("observer.host.ip")
        local host_fqdn = log_user_start:gets("observer.host.fqdn")
        local host_name = log_user_start:gets("observer.host.hostname")
        local path_name = log_user_auth:gets("initiator.process.path.full")
        local initiator_hostname = log_user_start:gets("initiator.host.hostname")
        local initiator_ip = log_user_start:gets("initiator.host.ip")

        if initiator_hostname == "?" then
           initiator_hostname = "Имя узла неопределено"
        end

        if initiator_ip == "?" then
           initiator_ip = "IP-адрес неопределен"
        end
        
-- Функция алерта
        alert({
            template = template,
            meta = {
                user_name1=initiator_username,
                user_name2=target_username,
                command_path=path_name,
                initiator_host=initiator_hostname,
                initiator_address=initiator_ip
                },
            risk_level = 6.0, 
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
        grouper1:clear()
        
        log_user_login = nil
        log_user_auth  = nil
        log_cred_acq   = nil
        log_user_start = nil

    end    
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)