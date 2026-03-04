whitelist = storage.new("wl_usernames|Linux: Подозрительная модификация задач в cron")

-- Шаблон алерта
local template = [[
	Подозрение на несанкционированную модификацию/добавление задач в cron.
    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователть(инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]

-- Переменные для групера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Массив с регулярными выражениями
local crontab_patterns = {
        "(?:^|\\/|\\s+|\"|\')crontab\\s+((-{1,2}[\\w=\\,\\s\\.]+){0,10})?((\\/?[^\\/ ]*)+\\/?)(?:$|\\/|\\s+|\"|\')",
        "(?:^|\\/|\\s+|\"|\')\\w+\\s+(?:(?:\'|\")[\\w\\s\'\";=><\\/\\.]+(?:\'|\")\\s+>{1,2}|[>\\|\\&]{1,2})\\s+(?:\\/etc\\/cron\\.(?:d|daily|hourly|monthly|weekly)|\\/var\\/spool\\/cron\\/crontabs)\\/\\S+"
    }

-- Для отсечения "простых" команд вроде crontab -l, crontab -r 
local crontab_info_command = "(?:^|\\/|\\s+|\"|\')crontab\\s+(-{1,2}[\\w=\\,\\s\\.]+)$"

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()
    local regular2 = cmd_string:search(crontab_info_command)

    if not regular2 then
        for _, pattern in pairs(crontab_patterns) do
            local regular1 = cmd_string:search(pattern)
            if regular1 then
                return regular1
            end
        end
    end
end

-- Функция работы с логлайном
function on_logline(logline)
    if logline:gets("observer.event.type") == "EXECVE" or logline:gets("observer.event.type") == "PROCTITLE" then
		local search_crontab = analyze(logline:gets("initiator.command.executed"))
        if search_crontab then
            grouper1:feed(logline)
		end
    else
-- Проверка на табличный список с именами пользователей-инициаторов
        if whitelist:get(logline:gets("initiator.user.name"), "username") == nil then
            grouper1:feed(logline)
        end
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local log_sys = nil
    local log_exec = nil

    for _, event in ipairs(events) do
        if event:gets("observer.event.type") == "SYSCALL" then
            log_sys = event
        else
            log_exec = event
        end
    end

-- Проверяем, что в группере находятся как события EXECVE/PROCTITLE, так и SYSCALL        
    if log_sys and log_exec then
            -- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name=log_sys:gets("initiator.user.name"),
                    command=log_exec:gets("initiator.command.executed"),
                    command_path=log_sys:gets("initiator.process.path.full")
                    },
                risk_level = 5.0, 
                asset_ip = log_exec:get_asset_data("observer.host.ip"),
                asset_hostname = log_exec:get_asset_data("observer.host.hostname"),
                asset_fqdn = log_exec:get_asset_data("observer.host.fqdn"),
                asset_mac = "",
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                logs = grouped.aggregatedData.loglines,
                mitre = {"T1053.003"},
                trim_logs = 10
                }
            )
            grouper1:clear()      
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)