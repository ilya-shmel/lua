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
local prefix = "(?:^|\\s+|\"|'|`|\\||&|\\\\)"
local pattern_read_copy = prefix.. "(?:copy|xcopy|move|robocopy|type|cat|more|get-content)((\\.exe)[\\,\'\"]+)?\\s+[^\\s]*\\.(?:txt|log|conf|config|ini|json|xml|yaml|yml|csv|dat|bak|cfg|properties|credentials|pwd|password|secret|key)"
local pattern_archive_transfer = prefix.. "(?:compress-archive|7z|rar|zip).*\\.(?:txt|log|conf|config|bak)|(?:^|\\s+|\"|'|`|\\||&|\\\\)(?:copy|xcopy|robocopy|curl|wget|invoke-webrequest).*(?:unattend\\.xml|sysprep\\.inf|\\.kdbx|\\.key|\\.pem|\\.ppk|credentials\\.txt|secrets\\.txt|web\\.config|\\.env)"
local pattern_search_export = prefix.. "(?:findstr|select-string|grep)\\s+.*(?:password|passwd|pwd|secret|credential|api[_-]?key|token|auth)|\\\\(?:windows\\\\system32\\\\config|etc|inetpub|programdata)\\\\.*\\.(?:txt|log|conf|ini|xml|cfg)|(?:^|\\s+|\"|'|`|\\||&)(?:out-file|export-csv|export-clixml|>|>>)\\s+[^\\s]*\\.(?:txt|log|csv|json|xml|conf|config|bak)"

local function analyze(cmd)
    cmd = cmd:lower()

    if cmd:search(whitelist_pattern) then
        return false
    end
    return cmd:search(pattern_read_copy) or cmd:search(pattern_archive_transfer) or cmd:search(pattern_search_export)
end

function on_logline(logline)
    local cmd = logline:gets("initiator.command.executed", "")
    
    if analyze(cmd) then
        grouper1:feed(logline)
    end
end

function on_grouped(grouped)
    if grouped.aggregatedData.aggregated.total >= 1 then
        local events = grouped.aggregatedData.loglines 
        local command_executed = events[1]:gets("initiator.command.executed")
        local path_execued = events[1]:gets("initiator.process.path.name") or events[1]:gets("target.image.name")
        local parent_path = events[1]:get("initiator.process.parent.path.original") or events[1]:get("initiator.process.path.name")
        local initiator_name = events[1]:get("initiator.user.name") or "Пользователь неопределен"

        if #command_executed > 128 then
            command_executed = command_executed:sub(1,128).. "... "
        end

        alert({
            template = template,
            meta = {
                command=command_executed,
                path=path_execued,
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