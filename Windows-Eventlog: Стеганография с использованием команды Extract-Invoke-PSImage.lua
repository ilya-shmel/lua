-- Шаблон алерта
local template = [[
Подозрение на применение стеганографии с использованием командлета Extract-Invoke-PSImage.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{.Meta.command}}
Процесс: {{.Meta.process}}   
]]

-- Параметры группера
local detection_window = "3m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "event.process.id"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Паттерны
local image_extentions = { ".jpg", ".bmp", ".gif", ".png", ".webp", ".raw", ".tiff", ".psd" }

-- Функция работы с логлайном
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")
    local process_id = logline:gets("observer.process.id")

    if compare(event_id, "==", "4104") then
        local command_executed = logline:gets("initiator.command.executed"):lower()
        
        if command_executed:match("function%sextract-invoke-psimage") then
            set_field_value(logline, "event.process.id", process_id)
            grouper1:feed(logline)    
        end
    elseif compare(event_id, "==", "4663") or compare(event_id, "==", "4656") then
        local object_name = logline:gets("target.object.name"):lower()
        local extention = object_name:match("%.%w+$")

        if contains(image_extentions, extention, "exact") then
            set_field_value(logline, "file.type", "image")    
        else 
            set_field_value(logline, "file.type", "data")
        end

        process_id = logline:gets("initiator.process.id")
        process_id = tonumber(process_id:gsub("^0[xX]", ""), 16) -- приводим к десятичному представлению для последующей группировки
        set_field_value(logline, "event.process.id", process_id)
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_command = nil
    local log_access_image = nil
    local log_access_data = nil
    local log_handle_image = nil
    local log_handle_data = nil

    if unique_events > 1 then
        for _, event in ipairs(events) then 
            local event_id = logline:gets("observer.event.id")
            local file_type = event:gets("file.type")
            
            if compare(event_id, "==", "4104") then
                log_command = event
            elseif compare(event_id, "==", "4663") then
                if file_type == "image" then
                    log_access_image = event
                else
                    log_access_data = event
                end
            elseif compare(event_id, "==", "4656") then
                if file_type == "image" then
                    log_handle_image = event
                else
                    log_handle_data = event
                end
            end
        end
        
        if log_command and (log_access_image or log_access_data) and (log_handle_image or log_handle_data) then
            local initiator_name = log_access_data:get("initiator.user.name") or 
            local host_ip = log_command:get("observer.host.ip") or log_command:get("reportchain.collector.host.ip")
            local host_name = log_command:gets("observer.host.hostname", "Имя узла не определено")
            local host_fqdn = log_command:gets("observer.host.fqdn", "FQDN узла не определено")
            local script_name = log_command:get("initiator.process.path.name", "Имя модуля не определено")
            local image_name = log_access_image:get("target.object.name") or log_handle_image:gets("target.object.name", "Имя файла неопределено")
            local data_name = log_access_data:get("target.object.name") or log_handle_data:gets("target.object.name", "Имя файла неопределено")
            local command_executed = log_command:gets("initiator.command.executed")
            local process_path = log_access_data:get("initiator.process.path.full") or log_handle_data:get("initiator.process.path.full") or log_access_image:gets("initiator.process.path.full") or log_handle_image:gets("initiator.process.path.full", "Путь неопределён")

            if #command_executed > 64 then
                command_executed = command_executed:sub(1, 64).. "... "
            end

             alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command=command_executed,
                    process=process_path,
                    script_name=service_name,
                    image_file=image_name,
                    data_file=data_name,
                    host_ip=host_ip,
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
                mitre = {"T1001.002"},
                trim_logs = 10
                }
            )
            grouper1:clear()
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)