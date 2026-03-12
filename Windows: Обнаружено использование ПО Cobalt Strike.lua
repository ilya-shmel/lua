-- Шаблоны алерта
local template = [[
	Обнаружено использование программного обеспечения Cobalt Strike.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"{{ .First.reportchain.collector.host.ip }}"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь (инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.path }}
]]

-- Переменные для группера
local detection_window = "3m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id", "event.thread.id"}
local aggregated_by = {"image.type"}
local grouped_time_field = "@timestamp,RFC3339"

local function set_type(event, image_type)
    set_field_value(event, "image.type", image_type)
    return event

end

-- Функция работы с логлайном
function on_logline(logline)
    local image_name = logline:gets("target.image.name")
    local event = nil
    
    if image_name:match("_server%.exe") then
        event = set_type(logline, "server")
    elseif image_name:match("_client%.exe") then
        event = set_type(logline, "client")
    else
        event = set_type(logline, "executor")
    end
    
    log("Image name: " ..tostring(image_name))
    log("Event type: " ..type(image_name))
    log("Event type: " ..type(logline))
    log("Event is: " ..tostring(event))

    
    grouper1:feed(event)
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total

    if unique_events > 2 then
       local initiator_name = events[1]:get("initiator.user.name") or "Пользователь не определен" 
       local host_ip = events[1]:get_asset_data("observer.host.ip") or events[1]:get_asset_data("reportchain.collector.host.ip")
       local host_name = events[1]:get_asset_data("observer.host.hostname")
       local host_fqdn = events[1]:get_asset_data("observer.host.fqdn")
       local command_executed = events[1]:gets("initiator.command.executed") or "Cobalt Strike"
       local command_path = events[1]:get("initiator.process.parent.path.original") or events[1]:get("target.process.path.full") or events[1]:get("target.image.name") or events[1]:get("event.logsource.application") or "C:\\Windows\\System32\\cmd.exe"
       
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
            mitre = {"T1055", "T1055.001", "T1055.012", "T1068", "T1559"},
            trim_logs = 10
            }
        )
       grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)