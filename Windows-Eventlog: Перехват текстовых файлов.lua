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
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "initiator.user.id", "initiator.user.name"}
local aggregated_by = {"target.image.name"}
local grouped_time_field = "@timestamp,RFC3339"

local whitelist_pattern = "(?:Microsoft\\.PowerShell\\.Cmdletization|\\$script:ClassName|\\$script:ObjectModelWrapper|ArchiveResources\\.psd1)"
local prefix = "(?:^|\\s+|\"|\'|`|\\||&|\\\\)"
local file_extention = "(?:txt|log|conf(?:ig)?|ini|json|xml|ya?ml|csv|dat|bak|cfg|properties|credentials|pwd|password|secret|key)"
local pattern_read_copy = prefix.. "(?:(?:x|robo)?copy|move|type|cat|more|get-content)(?:\\.exe)?\\s+[a-z]:\\\\[\\s\\S]*?\\." ..file_extention
local pattern_archive_transfer = prefix.. "(?:(?:x|robo)?copy|move|type|cat|more|get-content)(?:\.exe)?\\s+[a-z]:\\.*?\\.(?:txt|log|conf|config|bak|xml|inf|kdbx|key|pem|ppk|credentialstxt|secretstxt|webconfig|env)"
local pattern_search_export = prefix.. "(?:findstr|select-string|grep)\\s+[\\s\\S]*(?:password|passwd|pwd|secret|credential|api[_-]?key|token|auth)|\\\\(?:windows\\\\system32\\\\config|etc|inetpub|programdata)\\\\[\\s\\S]*\\\\.(?:txt|log|conf|ini|xml|cfg)|(?:out-file|export-csv|export-clixml|>|>>)\\s+[^\\s]*\\.(?:txt|log|csv|json|xml|conf|config|bak)"

local function analyze(cmd)
    cmd = cmd:lower()

    if cmd:search(whitelist_pattern) then
        return false
    end

-- ОТЛАДКА: проверяем каждую регулярку по отдельности
--    local match1 = cmd:search(pattern_read_copy)
--    local match2 = cmd:search(pattern_archive_transfer)
--    local match3 = cmd:search(pattern_search_export)
--    
--    if match1 or match2 or match3 then
--        -- Выводим в лог, какая именно регулярка сработала
--        log("=== REGEX MATCH DEBUG ===")
--        log("pattern_read_copy: " .. tostring(match1))
--        log("pattern_archive_transfer: " .. tostring(match2))
--        log("pattern_search_export: " .. tostring(match3))
--        log("First 200 chars of cmd: " .. cmd:sub(1, 20))
--        log("=========================")
--        return true
--    end
    return cmd:search(pattern_read_copy) or cmd:search(pattern_archive_transfer) or cmd:search(pattern_search_export) or false
end

function on_logline(logline)
    local cmd = logline:gets("initiator.command.executed", "")
    local event_id = logline:gets("observer.event.id", "")
    
    if tostring(event_id) == "4103" then
        cmd = cmd:lower()
        
        if cmd == "get-content" then
            local attr_value = logline:gets("target.object.attribute.value", "")
            local is_text_file = attr_value:search("\\.(?:txt|log|conf|config|ini|json|xml|yaml|yml|csv|dat|bak|cfg|properties|credentials|pwd|password|secret|key|inf)$")
            
            if is_text_file then
                grouper1:feed(logline)    
            end
        end
    else
        if analyze(cmd) then
            grouper1:feed(logline)
        end
    end
end

function on_grouped(grouped)
    if grouped.aggregatedData.aggregated.total >= 1 then
        local events = grouped.aggregatedData.loglines 
        local command_executed = events[1]:gets("initiator.command.executed")
        
        local path_name = events[1]:get("initiator.process.path.name")
        local image_name = events[1]:get("target.image.name")
        local attribute_value = events[1]:get("target.object.attribute.value")
        local service_name = events[1]:get("observer.service.name")

        local path_original = events[1]:get("initiator.process.parent.path.original")

        
        local path_executed = path_name or image_name or attribute_value or service_name or "Путь неопределён"
        local parent_path = path_original or path_name or service_name or "Процесс неопределён"
        local initiator_name = events[1]:get("initiator.user.name") or "Пользователь неопределен"

        if events[1]:get("observer.event.id") == 4104 then 
            path_executed = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            parent_path = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        end

        if #command_executed > 128 then
            command_executed = command_executed:sub(1,128).. "... "
        end

        alert({
            template = template,
            meta = {
                command=command_executed,
                path=path_executed,
                parent=parent_path,
                user_name=initiator_name
            },
            risk_level = 6.0,
            asset_ip = events[1]:get_asset_data("observer.host.ip"),
            asset_hostname = events[1]:get_asset_data("observer.host.hostname"),
            asset_fqdn = events[1]:get_asset_data("observer.host.fqdn"),
            asset_mac = "",
            create_incident = true,
            incident_group = "Collection",
            assign_to_customer = false,
            incident_identifier = events[1]:gets("observer.host.fqdn", "unknown") .. "_" .. events[1]:gets("initiator.user.id", "unknown"),
            logs = events,
            mitre = {"T1539", "T1005"},
            trim_logs = 10
        })
        
        grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)