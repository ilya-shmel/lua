-- Шаблон алерта
local template = [[
Подозрение на перехват cookie-файла.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{.Meta.command}}
Процесс: {{.Meta.process}}   
]]

-- Параметры группера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения, шаблоны
local cookies_patterns = { 
    stop_process_pattern = {
        pattern = "(stop-process|taskkill).*(-name|\\/im)\\s*(\"?)?(chrome|firefox|edge|opera|brave|msedge)|sqlite?\\.exe.*(cookies|moz_cookies|\\$env:[a-z]+.*cookie)"
    },
    select_pattern = {
        pattern = "select\\s+.*(encrypted_value|host_key|expires_utc|is_secure|is_httponly|samesite).*\\s+from\\s+\\[?(cookies|moz_cookies|cookie_data)\\]?"
    },
    sqlite_pattern = {
        pattern = "(sqlite-tools|sqlite[234]?\\.exe|sqlitebrowser\\.exe|db\\s+browser)|(dpapi|cryptunprotectdata|system\\.security\\.cryptography\\.protecteddata)"
    }
}

-- Стандартная функция анализа строки
local function analyze(cmd)
    local cmd = cmd:lower()

    for _, regex_table in pairs(cookies_patterns) do
        local is_stealing = cmd:search(regex_table.pattern) 
        
        if is_stealing then
            return is_stealing
        end
    end

    return false
end

-- Функция работы с логлайном
function on_logline(logline)
    local command_executed = logline:gets("initiator.command.executed")
    local is_stealing = analyze(command_executed)

    if is_stealing then
        grouper1:feed(logline)
    end
    
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local first_event = events[1]

    if #events > 0 then
        local initiator_name = first_event:get("initiator.user.name") or "Пользователь не определён" 
        local host_ip = first_event:get_asset_data("observer.host.ip") or first_event:get("reportchain.collector.host.ip")
        local host_name = first_event:get_asset_data("observer.host.hostname")
        local host_fqdn = first_event:get_asset_data("observer.host.fqdn")
        local service_name = first_event:get("target.service.name") or "Служба не определена"
        local command_executed = first_event:gets("initiator.command.executed")
        local process_path = first_event:get("initiator.process.path.full") or first_event:get("initiator.process.path.name") or first_event:get("evnt.logsource.application") or "Путь неопределён"

        if #command_executed > 128 then
            command_executed = command_executed:sub(1, 128).. "... "
        end

         alert({
            template = template,
            meta = {
                user_name=initiator_name,
                command=command_executed,
                process=process_path,
                service=service_name
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
            mitre = {"T1539"},
            trim_logs = 10
            }
        )
       grouper1:clear()
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)