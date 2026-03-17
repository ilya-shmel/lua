-- Шаблоны алерта
local template = [[
	Обнаружено извлечение данных учетных записей с отключенной предварительной аутентификацией в Kerberos.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь (инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.path }}
]]

-- Переменные для группера
local detection_window = "3m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Функция работы с логлайном
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")

    if event_id == 4768 or event_id == 4104 then
       grouper1:feed(logline) 
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total

    if unique_events > 1 then
       local initiator_name = events[1]:get("initiator.user.name") or "Пользователь не определен" 
       local host_ip = events[1]:get_asset_data("observer.host.ip")
       local host_name = events[1]:get_asset_data("observer.host.hostname")
       local host_fqdn = events[1]:get_asset_data("observer.host.fqdn")
       local command_executed = events[1]:gets("initiator.command.executed")
       local command_path = events[1]:get("initiator.process.parent.path.original") or events[1]:get("target.process.path.full") or events[1]:get("target.image.name") or events[1]:get("event.logsource.application")
       
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
            mitre = {"T1558.004"},
            trim_logs = 10
            }
        )
       grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)