function on_logline(logline)
    grouper:feed(logline)
end
function on_matched(grouped, matchedData)
    local logline = matchedData.loglines[1]
	alert({template = [[Разведка данных о системе с помощью нетипичных системных утилит

На хосте: "{{ .First.observer.host.ip }}" - "{{ .First.observer.host.hostname }}",
Пользователем: {{ if .First.initiator.user.name }} "{{ .First.initiator.user.name }}" {{ else }} "{{ .First.initiator.user.id }}" {{ end }}
Была выполнена команда: "{{ .First.initiator.command.executed}}"
Окружение, из которого выполнялась команда: {{ if .First.initiator.process.parent.path.original }} "{{ .First.initiator.process.parent.path.original}}". {{ else }} "{{ .First.observer.service.name}}".
{{ end }}]], risk_level = 7.0, asset_ip = logline:get_asset_data("observer.host.ip"), asset_hostname = logline:get_asset_data("observer.host.hostname"), asset_fqdn = logline:get_asset_data("observer.host.fqdn"), asset_mac = logline:get_asset_data(""), create_incident = true, incident_group = "", assign_to_customer = false, incident_identifier = "", logs = {logline}, mitre = {"T1210"}, trim_logs = 5})
end

local pattern = {
    {field = "target.image.name", values = {"cscript.exe", "wscript.exe"}, count = 1},
    {field = "target.image.name", values = {"rundll32.exe"}, count = 1},
    {field = "target.image.name", values = {"msiexec.exe"}, count = 4},
}

grouper = grouper.new_pattern_matcher({"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}, {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}, {"@timestamp"}, pattern, "@timestamp,RFC3339", "1m", on_matched)