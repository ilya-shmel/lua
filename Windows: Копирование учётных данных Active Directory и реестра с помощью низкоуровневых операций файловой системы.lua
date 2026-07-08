-- Шаблон алерта
local template = [[
Подозрение на копирование учётных данных Active Directory и реестра с помощью низкоуровневых операций файловой системы.

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{ or .Meta.ip "IP-адрес не определён" }}
Хост: {{ or .Meta.hostname "Имя узла не определено" }}
FQDN: {{ or .Meta.observer_fqdn "FQDN узла не определено" }}

ИНИЦИАТОР:
Пользователь: {{ or .Meta.user "Пользователь не определён"}}

ВЫПОЛНЕННАЯ КОМАНДА:
{{ .Meta.command }}
Процесс/Путь к имполняемому файлу: {{ .Meta.path }}
Скопированный файл: {{ .Meta.source_file }}
Целевой файл: {{ .Meta.destination_file }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "event.process.id"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local suspicious_pattern = [[[^\s]+\s+-\w+\s+m(?:ft|etadata)\s+-[^\s]+\s+(c:\\windows\\(([^\\-])+\\?)+)\s+-[^\s]+\s+\w:\\(([^\\-])+\\?)+]]

-- Функция оправляет событие в группер, предварительно проверив PID события
local function send_to_grouper(event, event_type)
    if event_type == "command" then
        local process_id = event:gets("observer.process.id")
    else
        local process_id = tonumber((event:gets("initiator.process.id")):gsub("^0[xX]", ""), 16) -- Преобразуем в десятичный формат
    end
    
    set_field_value(event, "event.process.id", process_id)
    grouper1:feed(event)
end

-- Функция сокразения строки для алерта
local function string_cut(cmd)
    if #cmd > 128 then
        cmd = cmd:sub(1, 128).. "... "
    end

    return cmd
end

-- Функция обработки логлайна
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")

    if compare(event_id, "==", "4104") then
        local command_executed = logline:gets("initiator.command.executed"):lower()

        if command_executed:search(suspicious_pattern) then
            send_to_grouper(logline, "command")
        end
    elseif compare(event_id, "==", "4103") then
        send_to_grouper(logline, "command")
    elseif compare(event_id, "==", "4663") then
        send_to_grouper(logline, "file")
    end
end

-- Функция группера #1
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_scriptblock, log_module, log_file
    
    log("Events: " ..#events.. ". Unique events: " ..unique_events)
    
    for _, event in ipairs(events) do
	    log("Event ID: " .. tostring(event:gets("observer.event.id")))
    end

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")

            if compare(event_id, "==", "4104") then
                log_scriptblock = event
            elseif compare(event_id, "==", "4103") then
                log_module = event
            else
                log_file = event
            end
        end

        if log_scriptblock and log_module and log_file then
            local initiator_name = log_module:gets("initiator.user.name")  
            local host_ip = log_scriptblock:get("observer.host.ip")
            local host_name = log_scriptblock:gets("observer.host.hostname")
            local host_fqdn = log_scriptblock:gets("observer.host.fqdn")
            local source_file = log_module:gets("target.object.name")
            local destination_file = log_file:gets("target.object.name")
            local command_executed = string_cut(log_scriptblock:gets("initiator.command.executed"))
            local process_path = log_file:get("initiator.process.path.full")

            alert({
               template = template,
               meta = {
                   user=initiator_name,
                   command=command_executed,
                   path=process_path,
                   source_file=source_file,
                   destination_file=destination_file,
                   ip=host_ip,
                   hostname=host_name
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
               logs = events,
               mitre = {"T1003.003"},
               trim_logs = 10
               }
            )
            grouper1:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)