-- Шаблон алерта
local template = [[
Подозрение на использование вредоносных динамически подключаемых библиотек.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{.Meta.command}}
Путь ветки реестра: {{.Meta.path}}
Имя параметра: {{.Meta.name}}
Старое значение: {{.Meta.old_value}}
Новое значение: {{.Meta.new_value}}
]]

-- Параметры группера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения, шаблоны
local new_value_pattern = "\\.dll$"
local old_value_pattern = "(\\.dll,)?\\.dll$"


-- Стандартная функция анализа строки
local function analyze(old_value, new_value)
    local old_value = old_value:lower()
    local new_value = new_value:lower()

    if old_value:search(old_value_pattern) then
        return false
    elseif new_value:search(new_value_pattern) then
        return true
    else
        return false
    end
end

-- Функция работы с логлайном
function on_logline(logline)
    local changes_new_value = logline:gets("target.config.changes.new_value")
    local changes_old_value = logline:gets("target.config.changes.old_value")
    local is_suspicious_dll = analyze(changes_old_value, changes_new_value)

    if is_suspicious_dll then
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local first_event = events[1]

    if #events > 0 then
        local initiator_name = first_event:gets("initiator.user.name")
        local changes_new_value = first_event:gets("target.config.changes.new_value")
        local changes_old_value = first_event:gets("target.config.changes.old_value") 
        local registry_path = first_event:gets("target.object.name")
        local registry_name = first_event:gets("target.object.original")
        local host_ip = first_event:get("observer.host.ip") or first_event:get("reportchain.collector.host.ip")
        local host_name = first_event:gets("observer.host.hostname")
        local host_fqdn = first_event:gets("observer.host.fqdn")
        local command_process = first_event:gets("initiator.process.path.full")

        alert({
            template = template,
            meta = {
                user_name=initiator_name,
                command=command_process,
                old_value=changes_old_value,
                new_value=changes_new_value,
                path=registry_path,
                name=registry_name,
                ip=host_ip,
                hostname=host_name
                },
            risk_level = 8.0, 
            asset_ip = host_ip,
            asset_hostname = host_name,
            asset_fqdn = host_fqdn,
            asset_mac = "",
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "",
            logs = events,
            mitre = {"T1556.008"},
            trim_logs = 10
            }
        )
       
       grouper1:clear()
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)