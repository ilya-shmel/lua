-- Шаблон алерта
local template = [[
Подозрение на переопределение системных команд.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Исполняемый файл: {{ .Meta.file_name }}
Среда исполнения: {{ .Meta.service }}
Набор выполненных команд: {{ .Meta.command }}
]]

-- Параметры группера
local detection_window = "5m"
local grouped_by = { "observer.host.ip", "observer.host.hostname", "event.process.id" }
local aggregated_by = { "observer.event.id" }
local grouped_time_field = "@timestamp,RFC3339"

-- Функция работы с логлайном
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")
    
    if compare(event_id, "==", "4688") then
        local process_id = logline:gets("initiator.process.parent.id")
        process_id = tonumber(process_id:gsub("^0[xX]", ""), 16) -- Преобразование из шестнадцатеричной системы в десятичную
        set_field_value(logline, "event.process.id", process_id)
    else   
        local process_id = logline:gets("observer.process.id")
        set_field_value(logline, "event.process.id", process_id)
    end
    
    grouper1:feed(logline)
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_webrequest = {}
    local log_webclient = {}
    
    --log("Events: " ..#events.. ". Unique events: " ..unique_events)

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")

            if compare(event_id, "==", "4103") then
                local object_name = event:gets("target.object.name"):lower()
                
                if object_name:find("webrequest") then
                    log_webrequest[1] = event
                else
                    log_webclient[1] = event
                end
            else    
                local command_executed = event:gets("initiator.command.executed"):lower()
                
                if command_executed:find("webrequest") then
                    log_webrequest[2] = event
                else
                    log_webclient[2] = event
                end
            end
        end
             
        if #log_webrequest > 1 and #log_webclient > 1 then 
            local initiator_name = log_webrequest[1]:gets("initiator.user.name", "Пользователь не определён")  
            local host_ip = log_webrequest[1]:get("observer.host.ip") or log_webrequest[1]:gets("reportchain.collector.host.ip", "IP-адрес не определён") 
            local host_name = log_webrequest[1]:gets("observer.host.hostname", "Имя узла не опредено")
            local host_fqdn = log_webrequest[1]:gets("observer.host.fqdn")
            local command_executed = log_webclient[2]:gets("initiator.command.executed") .. "; " .. log_webrequest[2]:gets("initiator.command.executed") 
            local service_path = log_webclient[1]:gets("initiator.command.executed")
            local script_name = log_webclient[1]:gets("initiator.file.name")

            if #command_executed > 128 then
                command_executed = command_executed:sub(1, 128).. "... "
            end
         
            alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command=command_executed,
                    service=service_path,
                    file_name=script_name,
                    host_ip=host_ip,
                    hostname=host_name
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
                mitre = { "T1059.001" },
                trim_logs = 10
                }
            )
            grouper1:clear()
        end
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)