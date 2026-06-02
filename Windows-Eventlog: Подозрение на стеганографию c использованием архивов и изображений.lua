-- Шаблон алерта
local template = [[
Возможно, обнаружено применение стеганографии с использованием архивов и изображений.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Исполняемый файл: {{ .Meta.service }}
Файл изображения: {{ .Meta.image }}
Архив: {{ .Meta.archive }}
Целевой файл: {{ .Meta.destination }}
]]

-- Параметры группера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "initiator.user.name"}
local aggregated_by = {"file.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Фаловые паттерны
local archive_extentions = { ".zip", ".rar", ".7z", ".tar", ".tarz", ".gz", ".bz", ".dat", ".cab", ".lha", ".arj", ".ace", ".z" }
local image_extentions = { ".jpg", ".bmp", ".gif", ".png", ".webp", ".raw", ".tiff", ".psd" }
local source_access_list = "%%4416" --Source RedData
local archive_access_list = { "%%4416", "%%4417", "%%4418" } --Archive RedData/Create Archive
local destination_access_list = { "%%4417", "%%4418", "%%4423" } --Destination Write

-- Функция работы с логлайном
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")
    local file_name = logline:gets("target.object.name"):lower()
    local ad_access_list = tostring(logline:gets("initiator.permissions.requested.ad_access_list"))
    
    log("EventID: " ..event_id.. ". User: " ..logline:gets("initiator.user.name").. ". File: " ..file_name.. ". Access list: " ..ad_access_list)

    if compare(event_id, "==", "4663") then
        if contains(image_extentions, file_name, "suffix") then
            if ad_access_list:search(source_access_list) then
                set_field_value(logline, "file.type", "source file")
                grouper1:feed(logline)
            elseif contains(destination_access_list, ad_access_list, "sub") then
                set_field_value(logline, "file.type", "destination file")
                grouper1:feed(logline)
            end
        elseif contains(archive_extentions, file_name, "suffix") then
            if contains(archive_access_list, ad_access_list, "sub") then
                set_field_value(logline, "file.type", "archive")
                grouper1:feed(logline)
            end
        end
    elseif compare(event_id, "==", "4656") then
        local access_mask = logline:gets("initiator.permissions.requested.access_mask")
        
        if contains(image_extentions, file_name, "suffix") and compare(access_mask, "==", "0x120196") and contains(destination_access_list, ad_access_list, "sub") then
            set_field_value(logline, "file.type", "destination file access")
            grouper1:feed(logline)
        end
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local source_event = nil
    local archive_event = nil
    local destination_event = nil
    local destination_access = nil

    log("Events: " ..#events.. ". Unique events: " ..unique_events)

    if unique_events > 3 then 

        for _, event in ipairs(events) do 
            local file_type = event:gets("file.type")
            if file_type == "source file" then
                source_event = event
            elseif file_type == "archive" then
                archive_event = event
            elseif file_type == "destination file" then
                destination_event = event
            elseif file_type == "destination file access" then 
                destination_access = event
            end
        end

        if source_event and archive_event and destination_event and destination_access then
            local initiator_name = destination_access:gets("initiator.user.name", "Пользователь не определён")  
            local host_ip = destination_event:get("observer.host.ip") or destination_event:get("reportchain.collector.host.ip")
            local host_name = destination_event:gets("observer.host.hostname", "Имя узла не определено")
            local host_fqdn = destination_event:gets("observer.host.fqdn")
            local service_name = destination_event:gets("initiator.process.path.full")
            local source_file = source_event:get("target.object.name")
            local archive_file = archive_event:get("target.object.name")
            local destination_file = destination_event:get("target.object.name")


            alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    service=service_name,
                    host_ip=host_ip,
                    hostname=host_name,
                    image=source_file,
                    archive=archive_file,
                    destination=destination_file
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
                mitre = {"T1001.002"},
                trim_logs = 10
                }
            )
            grouper1:clear()
        end    
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)