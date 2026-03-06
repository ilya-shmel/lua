local template = [[
Обнаружен перехват текстового файла.

Узел: {{ if and .First.observer.host.hostname .First.observer.host.ip }}{{ .First.observer.host.hostname }} ({{ .First.observer.host.ip }}){{ else if .First.observer.host.hostname }}{{ .First.observer.host.hostname }}{{ else if .First.observer.host.ip }}{{ .First.observer.host.ip }}{{ else }}Не определен{{ end }}
Пользователь: {{ if .First.initiator.user.name }}{{ .First.initiator.user.name }}{{ end }}{{ if and .First.initiator.user.name .First.initiator.user.id }} / {{ end }}{{ if .First.initiator.user.id }}{{ .First.initiator.user.id }}{{ end }}

Выполненные команды:
{{ range $i,$cmd := index .Grouped.aggregatedData.unique.data "initiator.command.executed" -}}
- {{ $cmd }}
{{ end -}}
{{ if .First.initiator.process.parent.path.original }}
Родительский процесс: {{ .First.initiator.process.parent.path.original }}{{ end }}
{{- if .First.initiator.process.path.name }}
Окружение: {{ .First.initiator.process.path.name }}{{ end }}]]

local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "initiator.user.id", "initiator.user.name"}
local aggregated_by = {"initiator.command.executed"}
local grouped_time_field = "@timestamp,RFC3339"

local whitelist_pattern = "(?i)(?:Microsoft\\.PowerShell\\.Cmdletization|\\$script:ClassName|\\$script:ObjectModelWrapper|ArchiveResources\\.psd1)"

local pattern_read_copy = "(?i)(?:^|\\s+|\"|'|`|\\||&|\\\\)(?:copy|xcopy|move|robocopy|type|cat|more|get-content)\\s+[^\\s]*\\.(?:txt|log|conf|config|ini|json|xml|yaml|yml|csv|dat|bak|cfg|properties|credentials|pwd|password|secret|key)"
local pattern_archive_transfer = "(?i)(?:^|\\s+|\"|'|`|\\||&|\\\\)(?:compress-archive|7z|rar|zip).*\\.(?:txt|log|conf|config|bak)|(?:^|\\s+|\"|'|`|\\||&|\\\\)(?:copy|xcopy|robocopy|curl|wget|invoke-webrequest).*(?:unattend\\.xml|sysprep\\.inf|\\.kdbx|\\.key|\\.pem|\\.ppk|credentials\\.txt|secrets\\.txt|web\\.config|\\.env)"
local pattern_search_export = "(?i)(?:^|\\s+|\"|'|`|\\||&|\\\\)(?:findstr|select-string|grep)\\s+.*(?:password|passwd|pwd|secret|credential|api[_-]?key|token|auth)|\\\\(?:windows\\\\system32\\\\config|etc|inetpub|programdata)\\\\.*\\.(?:txt|log|conf|ini|xml|cfg)|(?:^|\\s+|\"|'|`|\\||&)(?:out-file|export-csv|export-clixml|>|>>)\\s+[^\\s]*\\.(?:txt|log|csv|json|xml|conf|config|bak)"

local function analyze(cmd)
    if cmd:search(whitelist_pattern) then
        return false
    end
    return cmd:search(pattern_read_copy) or cmd:search(pattern_archive_transfer) or cmd:search(pattern_search_export)
end

function on_logline(logline)
    local cmd = logline:gets("initiator.command.executed", "")
    
    if cmd ~= "" and analyze(cmd) then
        grouper1:feed(logline)
    end
end

function on_grouped(grouped)
    if grouped.aggregatedData.aggregated.total >= 1 then
        local source = grouped.aggregatedData.loglines[1]
        
        alert({
            template = template,
            risk_level = 6.0,
            asset_ip = source:get_asset_data("observer.host.ip"),
            asset_hostname = source:get_asset_data("observer.host.hostname"),
            asset_fqdn = source:get_asset_data("observer.host.fqdn"),
            asset_mac = "",
            create_incident = true,
            incident_group = "Collection",
            assign_to_customer = false,
            incident_identifier = source:gets("observer.host.fqdn", "unknown") .. "_" .. source:gets("initiator.user.id", "unknown"),
            logs = grouped.aggregatedData.loglines,
            mitre = {"T1539", "T1005"},
            trim_logs = 10
        })
        
        grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)