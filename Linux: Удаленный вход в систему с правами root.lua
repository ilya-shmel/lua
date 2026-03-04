whitelist = storage.new("wl_hostnames|Linux: Удаленный вход в систему с правами root")

-- Шаблон алерта
local template = [[
	Обнаружен удаленный вход в систему род учетной записью root.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Окружение, из которого выполнен вход: {{ .Meta.command_path }}
    Узел, с которого выполнен вход: {{ .Meta.initiator_host }}
]]

-- Переменные для групера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "initiator.host.ip"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Массив с регулярными выражениями
local pattern = "(?:\\/|\'|\")?sshd"
local address_pattern = "(?:127(\\.0)+((\\.1)+)?|1?(?:0|255)(\\.(?:0|255)){3}|1(?:7|9)2\\.168?(\\.0){2}|169\\.254(\\.0){2})"

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
    local initiator_user = logline:gets("initiator.user.name")
    local initiator_ip = logline:gets("initiator.host.ip")
    
    if event_type == "USER_LOGIN" or event_type == "USER_AUTH" or event_type == "CRED_ACQ" or event_type == "USER_START" then
		ip_checker = analyze(initiator_ip,address_pattern)
        if initiator_user == "root" and result_name == "success" and not ip_checker then
            grouper1:feed(logline)
        end    
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_user_login = nil
    local log_user_auth = nil
    local log_cred_acq = nil
    local log_user_start = nil

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local type_event = event:gets("observer.event.type")

            if type_event == "USER_LOGIN" then
                log_user_login = event
            elseif type_event == "USER_AUTH" then
                log_user_auth = event
            elseif type_event == "CRED_ACQ" then
                log_cred_acq = event
            elseif type_event == "USER_START" then
                log_user_start = event
            end
        end

-- Проверяем, что в группере присутствуют все типы событий
        if log_user_login and log_user_auth and log_cred_acq and log_user_start then
            local initiator_name = log_user_start:gets("initiator.user.name")
            local host_ip = log_user_start:gets("observer.host.ip")
            local host_fqdn = log_user_start:gets("observer.host.fqdn")
            local host_name = log_user_start:gets("observer.host.hostname")
            local path_name = log_user_auth:gets("initiator.process.path.full")

            if whitelist:get(host_name, "hostname") == nil then

-- Функция алерта
                alert({
                    template = template,
                    meta = {
                        user_name=initiator_name,
                        command_path=path_name,
                        initiator_host=host_name
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
                    logs = events,
                    mitre = {"T1078"},
                    trim_logs = 10
                    }
                )
                grouper1:clear()      
            end
        end
    end    
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)