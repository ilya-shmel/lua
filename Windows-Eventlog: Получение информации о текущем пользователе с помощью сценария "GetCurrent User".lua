-- Шаблон алерта
local template = [[
{{ .Meta.title }}.

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{ or .Meta.ip "IP-адрес не определён" }}
Узел: {{ or .Meta.hostname "Имя узла не определено" }}
FQDN: {{ or .Meta.fqdn "FQDN узла не определено" }}

ИНИЦИАТОР:
Пользователь: {{ or .Meta.user "Пользователь не определён"}}

ВЫПОЛНЕННАЯ КОМАНДА:
{{ .Meta.command }}
Задействованные объекты: {{ .Meta.object }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "observer.process.id"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Шаблоны и паттерны
get_info_pattern = [[(?:^|"|'|:|\s+|\\|\/)getcurrent\(\)(?:$|\s+|;|'|")]]

-- Вспомогательная функция логирования значений
local function log_results(function_name, debug_info)
    log("=== function " .. function_name .. " ===")
    log("Table elements: " .. #debug_info)
    
    for _, line in ipairs(debug_info) do
        local label = line[1]
        local value = line[2]
        log(label .. tostring(value))
    end    
end

-- Функция алерта
local function alert_function(events, meta)
    alert({
        template = template,
        meta = meta,
        risk_level = meta.risk,
        asset_ip = meta.ip,
        asset_hostname = meta.hostname,
        asset_fqdn = meta.fqdn,
        asset_mac = "",
        create_incident = true,
        incident_group = "",
        assign_to_customer = false,
        incident_identifier = "",
        logs = events,
        mitre = meta.risk,
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
        if (logline:gets("initiator.command.executed"):lower()):search(get_info_pattern) then
            grouper1:feed(logline)
        end
    else
        grouper1:feed(logline)
    end
end

-- Функция группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_scriptblock, log_module    
    
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
            local meta = {
                user=log_module:gets("initiator.user.name"),
                command=string_cut(log_scriptblock:gets("initiator.command.executed")),
                object=log_module:gets("target.object.name"),
                ip=log_scriptblock:gets("observer.host.ip"),
                hostname=log_scriptblock:gets("observer.host.hostname"),
                fqdn=log_scriptblock:gets("observer.host.fqdn"),
                risk=6.0,
                mitre={"T1033"},
                title="Обнаружено выполнение команды 'GetCurrent User' для получения сведений о пользователе"            
            }

            alert_function(events, meta)
            grouper1:clear()
        end
    end

    local debug_info = {
        {"Events: ", #events },
        {"Unique events: ", unique_events}
    }

    log_results("on_grouped", debug_info)
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)