function on_logline(logline)
	grouper:feed(logline)
end
function on_matched(grouped, matchedData)
    local logline = matchedData.loglines[1]
    alert({template = [[Подозрение на фишинг.

На узле: "{{ .First.observer.host.ip }}" - "{{ .First.observer.host.hostname }}",
Пользователем: {{ if .First.initiator.user.name }} "{{ .First.initiator.user.name }}" {{ else }} "{{ .First.initiator.user.id }}" {{ end }}
Была выполнена команда: "{{ .First.initiator.command.executed}}"
Окружение, из которого выполнялась команда: {{ if .First.initiator.process.parent.path.original }} "{{ .First.initiator.process.parent.path.original}}". {{ else }} "{{ .First.observer.service.name}}".
{{ end }}]],
    risk_level = 8.0, 
    asset_ip = logline:get_asset_data("observer.host.ip"),
    asset_hostname = logline:get_asset_data("observer.host.hostname"),
    asset_fqdn = logline:get_asset_data("observer.host.fqdn"),
    asset_mac = logline:get_asset_data(""),
    create_incident = true, incident_group = "",
    assign_to_customer = false,
    incident_identifier = "",
    logs = {logline},
    mitre = {"T1566"},
    trim_logs = 5})
end

local pattern = {
    {field = "target.image.name", values = {"powershell.exe"}, count = 3},
    {field = "target.image.name", values = {"locker.exe", "SharpeExfiltrate.exe", "MEGACmd.exe", "Gmer.exe", "PowerTool64.exe", "Anydesk.exe", "TeamViewer.exe", "Support.exe"}, count = 3},
    {field = "target.image.name", values = {"vssadmin.exe"}, count =1}
}

grouper = grouper.new_pattern_matcher({"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}, {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}, {"@timestamp"}, pattern, "@timestamp,RFC3339", "5m", on_matched)