whitelist = storage.new("tty_users|Linux: Вход в систему был выполнен из консоли")

-- Шаблон алерта
local template = [[
	Обнаружен вход в систему из консоли (tty).

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Пользователь(целевой): {{ .Meta.target_user }}
    Окружение, из которого выполнен вход: {{ .Meta.command_path }}
    Имя консоли: {{ .Meta.shell }}
]]

-- Переменные для групера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "target.user.name"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Массив с регулярными выражениями
local terminal_pattern = "(\\/dev\\/)?(?:ttys?\\d{1,2}|console)"
local app_pattern = "\\/usr\\/bin\\/login"

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
    local shell_name = logline:gets("initiator.shell.name")        
    local path_name = logline:gets("initiator.process.path.full")

    if event_type == "USER_LOGIN" or event_type == "USER_START" then
		terminal_check = analyze(shell_name, terminal_pattern)
        path_check = analyze(path_name, app_pattern)

        local my_terminal = tostring(terminal_check)
        local my_path = tostring(path_check)

        if terminal_check and path_check and result_name == "success" then
            grouper1:feed(logline)
        end    
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local log_user_login = ""
    local log_user_start = ""

    for _, event in ipairs(events) do
        local type_event = event:gets("observer.event.type")
       
        if type_event == "USER_LOGIN" then
            log_user_login = event
        else 
            log_user_start = event
        end        
    end

-- Проверяем, что в группере находятся как события EXECVE/PROCTITLE, так и SYSCALL
    if (log_user_login or "") ~= "" and (log_user_start or "") ~= "" then
        local initiator_name = log_user_start:gets("initiator.user.name")
        local target_name = log_user_start:gets("target.user.name")
        local host_shell = log_user_start:gets("initiator.shell.name")
        local host_ip = log_user_start:gets("observer.host.ip")
        local host_fqdn = log_user_start:gets("observer.host.fqdn")
        local host_name = log_user_start:gets("observer.host.hostname")
        local path_name = log_user_start:gets("initiator.process.path.full")
        local user_check = whitelist:get(target_name, "username")

        if not user_check then
-- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    target_user=target_name,
                    command_path=path_name,
                    initiator_host=host_name,
                    shell=host_shell
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
        end    
    end    
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)