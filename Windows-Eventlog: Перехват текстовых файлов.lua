local template = [[
Обнаружен перехват текстового файла.

Узел: {{ if and .First.observer.host.hostname .First.observer.host.ip }}{{ .First.observer.host.hostname }} ({{ .First.observer.host.ip }}){{ else if .First.observer.host.hostname }}{{ .First.observer.host.hostname }}{{ else if .First.observer.host.ip }}{{ .First.observer.host.ip }}{{ else }}Не определен{{ end }}
Пользователь: {{ if .First.initiator.user.name }}{{ .First.initiator.user.name }}{{ end }}{{ if and .First.initiator.user.name .First.initiator.user.id }} / {{ end }}{{ if .First.initiator.user.id }}{{ .First.initiator.user.id }}{{ end }}

Выполненные команды:
Пользователь (инициатор): {{ .Meta.user_name }}
Выполненная команда: {{ .Meta.command }}
Окружение, из которого выполнялась команда: {{ .Meta.path }}
Родительский процесс: {{ .Meta.parent}}
]]

local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "initiator.process.id"}
local aggregated_by = {"target.directory.name"}
local grouped_time_field = "@timestamp,RFC3339"

local child_attributes = { "%%4417", "%%4423", "%%1539" }


function on_logline(logline)
    local file_type = nil
    local file_fullname = logline:gets("target.object.name") 
    local file_name = file_fullname:match("[^\\]+$")
    local directory_name = file_fullname:gsub("[^\\]+$", ""):gsub("\\$", "")
    local ad_access_list = logline:gets("initiator.permissions.requested.ad_access_list")
    local attribute_value = logline:gets("target.object.attribute.value"):lower()
    
    log("File: " ..file_name.. ", Dirname: " .. directory_name)

    if contains(child_attributes, attributes, "sub") and compare(attribute_value, "s:ai", "==") then 
        set_field_value(logline, "file.type", "destination file")
    else
        set_field_value(logline, "file.type", "source file")
    end
    
    set_field_value(logline, "target.file.name", file_name)
    set_field_value(logline, "target.directory.name", directory_name)
    grouper1:feed(logline)
end

function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local parent_file_event = nil
    local child_file_event = nil
    log("Events: " ..#events.. ". Unique events: " ..unique_events)
     
    if unique_events > 1 then
        for _, event in ipairs(events) do
            local file_type = event:gets("file.type")
            
            if file_type == "source file" then
                parent_file_event = event
            elseif file_type == "destination file" then
                child_file_event = event
            end
        end
        

        if parent_file_event and child_file_event then
            local program_name = parent_file_event:get("initiator.process.path.full") or child_file_event:get("initiator.process.path.full")
            local parent_filename = parent_file_event:get("target.object.name")
            local child_filename = child_file_event:get("target.object.name")
            local initiator_name = parent_file_event:get("initiator.user.name") or child_file_event:gets("initiator.user.name", "Пользователь не определён")
            local host_ip = parent_file_event:gets("observer.host.ip", "IP-адрес узла не определён")
            local host_name = parent_file_event:gets("observer.host.hostname", "Имя узла не определёно")
            local host_fqdn = parent_file_event:gets("observer.host.fqdn", "FQDN узла не определёно")

            alert({
                template = template,
                meta = {
                    command=program_name,
                    parent=parent_filename,
                    child=child_filename,
                    user_name=initiator_name,
                    ip=host_ip,
                    hostname=host_name
                },
                risk_level = 6.0,
                asset_ip = host_ip,
                asset_hostname = host_name,
                asset_fqdn = host_fqdn,
                asset_mac = "",
                create_incident = true,
                incident_group = "Collection",
                assign_to_customer = false,
                logs = events,
                mitre = {"T1539", "T1560"},
                trim_logs = 10
            })
            grouper1:clear()
        elseif not parent_file_event then
            error("==No parent events==")
        elseif not child_file_event then
            error("==No child events==")
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)