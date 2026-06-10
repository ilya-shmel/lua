-- Шаблон алерта
local template = [[
Подозрение на использование потенциально вредоносных командлетов PowerShell.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{.Meta.command}}
Процесс: {{ .Meta.process}}
Тип угрозы: {{ .Meta.threat_caption}}   
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.process.id"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Функция работы с логлайном
function on_logline(logline)
    grouper1:feed(logline)
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_scriptblock = nil
    local log_module = nil

    if unique_events > 1 then
        for _, event in ipairs(events)
            local event_id = event:gets("observer.event.id")

            if compare(event_id, "==", "4104") then
                log_scriptblock = event
            else
                log_module = event
            end
        end
        
        if log_scriptblock and log_module then 
            local initiator_name = log_module:gets("initiator.user.name", "Пользователь не определён")  
            local host_ip = log_scriptblock:get("observer.host.ip") or log_scriptblock:gets("reportchain.collector.host.ip", "IP-адрес не определён") 
            local host_name = log_scriptblock:gets("observer.host.hostname")
            local host_fqdn = log_scriptblock:gets("observer.host.fqdn")
            local command_executed = log_scriptblock:gets("initiator.command.executed")
            local cmdlet  = log_module:gets("target.object.name")
            
            if #command_executed > 128 then
                command_executed = command_executed:sub(1, 128).. "... "
            end

             alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command=command_executed,
                    cmndlet=cmdlet,
                    hostname=host_name,
                    host_ip=host_ip
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
                mitre = {"T1059.001"},
                trim_logs = 10
                }
            )
            grouper1:clear()
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)