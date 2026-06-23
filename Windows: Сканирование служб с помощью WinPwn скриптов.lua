-- Шаблоны алерта
local template = [[
	Обнаружено сканирование с помощью скрипта "WinPwn" ("spoolvulnscan", "MS17-10", "bluekeep", "fruit").

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь (инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.path }}
]]

-- Переменные для группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.process.id"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Функция работы с логлайном
function on_logline(logline)
    grouper1:feed(logline)
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_scriptblock = nil
    local log_module = {}

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")

            if compare(event_id, "==", "4103") then
                table.insert(log_module, event)
            else 
                log_scriptblock = event
            end

        end

        if log_scriptblock and #log_module > 1 then
            local log_module_first_event = log_module[1]
            local initiator_name = log_module_first_event:get("initiator.user.name") or "Пользователь не определен" 
            local host_ip = log_scriptblock:get("observer.host.ip") or log_scriptblock:get("reportchain.collector.host.ip")
            local host_name = log_scriptblock:gets("observer.host.hostname", "Имя узла не опредено")
            local host_fqdn = log_scriptblock:gets("observer.host.fqdn")
            local command_executed = log_scriptblock:gets("initiator.command.executed")
            local command_path = log_scriptblock:get("initiator.process.parent.path.original") or log_scriptblock:get("target.process.path.full") or log_scriptblock:get("target.image.name") or log_scriptblock:gets("event.logsource.application", "Путь неопределён")
       
            if #command_executed > 128 then
                 command_executed = command_executed:sub(1,128).. "..."
            end

            alert({
                 template = template,
                 meta = {
                     user_name=initiator_name,
                     command=command_executed,
                     path=command_path
                     },
                 risk_level = 4.0, 
                 asset_ip = host_ip,
                 asset_hostname = host_name,
                 asset_fqdn = host_fqdn,
                 asset_mac = "",
                 create_incident = true,
                 incident_group = "",
                 assign_to_customer = false,
                 incident_identifier = "",
                 logs = events,
                 mitre = {"T1046", "T1615", "T1558.003", "T1558.004", "T1187", "T1082", "T1518"},
                 trim_logs = 10
                 }
            )
            grouper1:clear()
    
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)