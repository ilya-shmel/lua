-- Шаблон алерта
local template = [[
	Зафиксировано повышение привилегий.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
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
local escalation_patterns = {
        "(?:^|\\/|\\s+|\"|\')sudo\\s+(?:apt|pip)\\s+(?:install|update)\\s+(-\\w\\s+)?(?:(?:\\/[^\\/\\s]*)+(\\s+\\w{2})?|[\\w:-]+=\\/bin\\/(\\w+)?sh)",
        "(?:^|\\/|\\s+|\"|\')fpm\\s+(-\\w\\s+\\w+\\s+)+--before-install\\s+\\/tmp\\/([^\\/\\s]*)+\\/\\w+.sh\\s+(\\/[^\\/\\s]*)+",
        "(?:^|\\/|\\s+|\"|\')sudo\\s+docker\\s+\\w+\\s+-\\w\\s+[\\/:\\w]+\\s+(?:-{1,2}\\w+\\s+)+\\w+\\s+chroot\\s+\\/\\w+\\s+(\\w{1,2})?sh",
        "(?:^|\\/|\\s+|\"|\')sudo\\s+(?:find|gcc)\\s+(\\.\\s+)?-(?:exec|wrapper)\\s+\\/bin\\/(\\w{1,2})?sh[\\s\\,\\;]+-(?:quit|s)(\\s+\\.)?",
        "(?:^|\\/|\\s+|\"|\')sudo\\s+\\w+=(?:\'|\")?(\\w+)?sh\\s+-c\\s+(?:\'|\")?exec\\s+(\\w+)?\\s+[\\d<&]+(?:\'|\")?\\s+git\\s+[-\\w\\s]+",
        "(?:^|\\/|\\s+|\"|\')sudo\\s+git\\s+-{1,2}[\\w\\-=\\s]+\\/tmp(\\/[^\\/\\s]*)+\\s+(commit)?(\\s+)?((-{1,2}(?:allow-empty|m)\\s+){1,10})?x",
        "(?:^|\\/|\\s+|\"|\')sudo\\s+(?:vi(m)?|apt(-get)?|dmesg|git)\\s+(?:changelog\\s+apt|branch)?([-\\s\\w]{2,7})?(?:\\s+config|\':!(\\/[^\\/\\s]+)\\/sh\'\\s+(\\/[^\\/\\s]+)*\\/?)?",
        "(?:^|\\/|\\s+|\"|\')sudo\\s+make\\s+([-\\w\\s=:]+)+-\\/bin\\/(\\w{1,2})?sh",
        "(?:^|\\/|\\s+|\"|\')sudo\\s+openvpn\\s+([-\\w\\s=:]+)+\\/bin\\/(\\w{1,2})?sh\\s+-c\\s+(\\w{1,2})?sh",
        "(?:^|\\/|\\s+|\"|\')sudo\\s+python[\\d\\.]+\\s+([-\\w;\\.\\s]+)\\((?:\"|\')?\\/bin\\/(\\w{1,2})?sh(?:\"|\')?\\)"
}
-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()
    
    for _, pattern in pairs(escalation_patterns) do
            local regular = cmd_string:search(pattern)
            if regular then
                return regular
            end
        
    end
end

-- Функция работы с логлайном
function on_logline(logline)
    if logline:gets("observer.event.type") == "EXECVE" or logline:gets("observer.event.type") == "PROCTITLE" then
		local search_escalation = analyze(logline:gets("initiator.command.executed"))
        if search_escalation then
            grouper1:feed(logline)
		end
    else
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local log_sys = ""
    local log_exec = ""

    for _, event in ipairs(events) do
        if event:gets("observer.event.type") == "SYSCALL" then
            log_sys = event
        else
            log_exec = event
        end
    end

-- Проверяем, что в группере находятся как события EXECVE/PROCTITLE, так и SYSCALL        
    if log_sys ~= "" and log_exec ~= "" then
        local command_executed=log_exec:gets("initiator.command.executed")
        local command_length=command_executed:len().. "..."
        if command_length > 128 then
            command_executed=command_executed:sub(1,128)
        end
        -- Функция алерта
        alert({
            template = template,
            meta = {
                user_name=log_sys:gets("initiator.user.name"),
                command=command_executed,
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
            mitre = {"T1068"},
            trim_logs = 10
            }
        )
        grouper1:clear()      
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)