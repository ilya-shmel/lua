-- Шаблон алерта
local template = [[
Подозрение на попытку разведки подключённых периферийных устройств.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{.Meta.command}}
]]

-- Параметры группера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения для обнаружения разведки устройств
local browser_data = "(?:^|\\s+|\"|\'|`|\\||&|\\\\)(?:chrome|microsoft\\s+edge|mozilla|opera\\s+software|yandexbrowser)\\(?:user\\s+data|firefox|opera\\s+stable)\\"

-- Основная функция анализа
local function analyze(cmd, image_name)
    local detected, techniques = analyze_device_enumeration(cmd, image_name)
    
    if #detected > 0 then
        return {detected = detected, techniques = techniques}
    end
    
    return false
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")
    
    if event_id == 5145 then
        local file_path = logline:gets("target.file.path")
        local path_full = logline:gets("target.object.path.full")
        local is_browser_file = analyze(file_path) or analyze(path_full)
    elseif event_id == 5145 then 
        local target_name = logline:gets("target.object.name")
        local is_browser_file = analyze(target_name)
    end

    if is_browser then
            grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local audit_detailed_event = nil
    local access_event = nil
    
    if unique_events > 1 then 
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")
            if event_id == 5145 then
                audit_detailed_event = event
            else
                access_event = event
            end
        end

        local initiator_name = audit_detailed_event:get("initiator.user.name") or "Пользователь не определён"
        local host_ip = audit_detailed_event:get("observer.host.ip") or first_event:get("reportchain.collector.host.ip")
        local host_name = audit_detailed_event:get("observer.host.hostname") or "Имя узла не определено"
        local host_fqdn = audit_detailed_event:get("observer.host.fqdn") or "FQDN не определено"
        local process_path = access_event:get("initiator.process.path.full") or access_event:get("initiator.process.path.name") or "Путь не определён"
        
        alert({
            template = template,
            meta = {
                user_name = initiator_name,
                process = process_path,
                host_ip = host_ip,
                hostname = host_name,
            },
            risk_level = 7.0,
            asset_ip = host_ip,
            asset_hostname = host_name,
            asset_fqdn = host_fqdn,
            asset_mac = "",
            create_incident = true,
            incident_group = "Browser Data Collection",
            assign_to_customer = false,
            logs = events,
            mitre = {"T1539"},
            trim_logs = 10
        })

        grouper1:clear()
    end
end

-- Инициализация группера
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)