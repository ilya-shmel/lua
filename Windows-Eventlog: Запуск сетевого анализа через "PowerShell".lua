-- Шаблон алерта
local template = [[
	Обнаружено выполнение команд сетевого анализа в PowerShell.

	Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    ID пользователя: {{ .Meta.user_id }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]

-- Переменные для группера
local detection_window = "3m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}
local aggregated_by = {"operation.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Функция работы с логлайном
function on_logline(logline)
    local command_executed = logline:gets("initiator.command.executed"):lower()

    if command_executed:match("^new-") then
        set_field_value(logline, "operation.type", "new")
    elseif command_executed:match("^add-") then
        set_field_value(logline, "operation.type", "add")
    elseif command_executed:match("^start-") then
        set_field_value(logline, "operation.type", "start")
    elseif command_executed:match("^stop-") then
        set_field_value(logline, "operation.type", "stop")
    elseif command_executed:match("^remove-") then
        set_field_value(logline, "operation.type", "remove")
    end
    
    grouper1:feed(logline)
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local commands_executed = {}

    if unique_events > 2 then
        for _, event in ipairs(events) do
            local current_command = event:gets("initiator.command.executed")
            table.insert(commands_executed, current_command)
        end
    

        local all_commands = table.concat(commands_executed, "; ")

        if #all_commands > 128 then
            all_commands = all_commands:sub(1,128).. "..."
        end

        local initiator_user = events[1]:get("initiator.user.name") or "Не установлен"
        local initiator_id = events[1]:get("initiator.user.id") or "Не установлен"
        local path = events[1]:gets("observer.service.name")
-- Функция алерта
        alert({
            template = template,
            meta = {
                user_name=initiator_user,
                user_id=initiator_id,
                command=all_commands,
                command_path=path
                },
            risk_level = 4.0, 
            asset_ip = events[1]:get_asset_data("observer.host.ip"),
            asset_hostname = events[1]:get_asset_data("observer.host.hostname"),
            asset_fqdn = events[1]:get_asset_data("observer.host.fqdn"),
            asset_mac = events[1]:get_asset_data(""),
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "",
            logs = events,
            mitre = {"T1040"},
            trim_logs = 10
            }
        )
        grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)