-- Шаблон алерта
local template = [[
Подозрение на обратимое шифрование Active Directory.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{.Meta.command}}
Процесс: {{.Meta.process}}   
]]

-- Параметры группера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения, шаблоны
local prefix = "(?:^|\\/|\\s+|\"|\'|\\\\)"
local ad_encryption_patterns = { 
                                "(\\s+?-(?:filter|properties)\\s+[{\"\']allowreversiblepasswordencryption[-$\\s\\w]*?[}\"\'][\\s$]?){2}",
                                "([\\/;]invoke-dcsync(\\.ps1)?[)\\s]+(-alldata$)?){2}"
}

-- Стандартная функция анализа строки
local function analyze(cmd)
    local cmd = cmd:lower()

    for _, pattern in pairs(ad_encryption_patterns) do
        local is_encryption = cmd:search(pattern) 
        
        if is_encryption then
            return true
        end
    end

    return false
end

-- Функция работы с логлайном
function on_logline(logline)
    local command_executed = logline:gets("initiator.command.executed")
    local is_encryprion = analyze(command_executed)

    if is_encryprion then
        grouper1:feed(logline)
    end
    
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local first_event = events[1]

    if #events > 0 then
        local initiator_name = first_event:gets("initiator.user.name", "Пользователь не определён")  
        local host_ip = first_event:get("observer.host.ip") or first_event:get("reportchain.collector.host.ip")
        local host_name = first_event:gets("observer.host.hostname", "Имя узла не определено")
        local host_fqdn = first_event:gets("observer.host.fqdn")
        local service_name = first_event:get("target.service.name") or "Служба не определена"
        local command_executed = first_event:gets("initiator.command.executed")
        local process_path = first_event:get("initiator.process.path.full") or first_event:get("initiator.process.path.name") or first_event:gets("event.logsource.application", "Путь неопределён")

        if #command_executed > 128 then
            command_executed = command_executed:sub(1, 128).. "... "
        end

         alert({
            template = template,
            meta = {
                user_name=initiator_name,
                command=command_executed,
                process=process_path,
                service=service_name,
                host_ip=host_ip,
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
            mitre = {"T1556.005"},
            trim_logs = 10
            }
        )
       
       grouper1:clear()
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)