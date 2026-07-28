-- Шаблон алерта
local template = [[
Детектирование автоматизированного перехвата трафика с записью в PCAP-файлы.

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{ or .Meta.ip "IP-адрес не определён" }}
Узел: {{ or .Meta.hostname "Имя узла не определено" }}
FQDN: {{ or .Meta.fqdn "FQDN узла не определено" }}

ИНИЦИАТОР:
Пользователь: {{ or .Meta.user "Пользователь не определён"}}

ВЫПОЛНЕННАЯ КОМАНДА:
{{ .Meta.command }}
Имя программы: {{ .Meta.program }}
Процесс/Путь к иcполняемому файлу: {{ .Meta.path }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn","target.object.name"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local cap_pattern = [[(?:^|\s+|"|'|\\)(?:windump|tshark)(\.exe)?[\\\s"'\:;)](\s+)?[^\\]+\w:[\s\S]*?\.pcap(\w+)?]]
local file_pattern = "%s+[\'\"]?(%a:\\[^\"\']+%.%w+)[\'\"]?"

-- Вспомогательная функция логирования значений в группере (удалить после тестирования на потоке)
local function log_grouper(events, events_number, unique_events, grouper_name, grouper_field)
    log("### " .. grouper_name .. " ###")
    log("Events: " ..#events.. ". Unique events: " ..unique_events)
    
    for _, event in ipairs(events) do
	    log("Event ID: " .. tostring(event:gets("observer.event.id")))
        log("Grouper field: " .. tostring(event:gets(grouper_field))) 
    end    
end

-- Функция алерта
local function alert_function(events, meta)
    alert({
        template = template,
        meta = meta,
        risk_level = 7.0, 
        asset_ip = meta.ip,
        asset_hostname = meta.hostname,
        asset_fqdn = meta.fqdn,
        asset_mac = "",
        create_incident = true,
        incident_group = "",
        assign_to_customer = false,
        incident_identifier = "",
        logs = events,
        mitre = {"T1020.001"},
        trim_logs = 10
        }
     )
end

-- Функция сокращения строки для алерта
local function string_cut(cmd)
    if #cmd > 128 then
        cmd = cmd:sub(1, 128).. "... "
    end

    return cmd
end

-- Функция обработки логлайна
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")

    if compare(event_id, "==", "4688") then
        local command_executed = logline:gets("initiator.command.executed")
        local command_lower = command_executed:lower()
        
        if command_lower:search(cap_pattern) then
            local file_name = command_executed:match(file_pattern)
            set_field_value(logline, "target.object.name", file_name)
            grouper1:feed(logline)
        end
    else
        grouper1:feed(logline)
    end
    
end

-- Функция группера #1
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec, log_file
    
    log_grouper(events, #events, unique_events, "on_grouped", grouped_by[4])

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")

            if compare(event_id, "==", "4688") then
                log_exec = event
            else
                log_file = event
            end
        end

        if log_exec and log_file then
            local meta = {
                user=log_exec:gets("initiator.user.name"),
                command=string_cut(log_exec:gets("initiator.command.executed")),
                path=log_exec:get("target.process.path.full"),
                program=log_exec:gets("target.image.name"),
                parent=log_exec:gets("initiator.process.parent.path.original"),
                file=log_file:gets("target.object.name"),
                ip=log_exec:get("observer.host.ip"),
                hostname=log_exec:gets("observer.host.hostname"),
                fqdn=log_exec:gets("observer.host.fqdn")    
            }
            
            alert_function(events, meta)
            grouper1:clear()
        end

    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)