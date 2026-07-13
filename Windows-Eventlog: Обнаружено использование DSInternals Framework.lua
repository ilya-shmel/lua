-- Шаблон алерта
local template = [[
Обнаружено использование утилиты DSInternals.

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{ or .Meta.ip "IP-адрес не определён" }}
Узел: {{ or .Meta.hostname "Имя узла не определено" }}
FQDN: {{ or .Meta.fqdn "FQDN узла не определено" }}

ИНИЦИАТОР:
Пользователь: {{ or .Meta.user "Пользователь не определён"}}

ВЫПОЛНЕННАЯ КОМАНДА:
{{ .Meta.command }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "observer.process.id"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local dsinternals_pattern = [[(?:^|\/|\s+|"|'|\()get-adreplaccount\s+-[^-]*-server\s+[\s\S]*]]

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
local function alert_function(events, ip, hostname, fqdn, user, cmd)
    alert({
        template = template,
        meta = {
            user=user,
            command=cmd,
            path=path,
            program=program,
            service=service,
            ip=ip,
            hostname=hostname,
            fqdn=fqdn
            },
        risk_level = 8.0, 
        asset_ip = ip,
        asset_hostname = hostname,
        asset_fqdn = fqdn,
        asset_mac = "",
        create_incident = true,
        incident_group = "",
        assign_to_customer = false,
        incident_identifier = "",
        logs = events,
        mitre = {"T1003.006"},
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
    
    if compare(event_id, "==", "4104") then
       local command_executed = logline:gets("initiator.command.executed"):lower()

        if command_executed:search(dsinternals_pattern) then
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
    local log_scriptblock, log_module
    
--    log_grouper(events, #events, unique_events, "on_grouped", grouped_by[4])

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")

            if compare(event_id, "==", "4104") then
                log_scriptblock = event
            else
                log_module = event
            end
        end

        if log_scriptblock and log_module then
            local initiator_name = log_module:gets("initiator.user.name")  
            local host_ip = log_scriptblock:get("observer.host.ip")
            local host_name = log_scriptblock:gets("observer.host.hostname")
            local host_fqdn = log_scriptblock:gets("observer.host.fqdn")
            local command_executed = string_cut(log_scriptblock:gets("initiator.command.executed"))

            alert_function(events, host_ip, host_name, host_fqdn, initiator_name, command_executed)
            grouper1:clear()
        end

    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)