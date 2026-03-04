function on_logline(logline)
	grouper1:feed(logline)
    grouper2:feed(logline)
end
function on_matched(grouped, matchedData)
	local logline = matchedData.loglines[1]
	alert({template = [[Подозрение на подмену системного файла

На хосте: "{{ .First.observer.host.ip }}" - "{{ .First.observer.host.hostname }}",
Пользователем: {{ if .First.initiator.user.name }} "{{ .First.initiator.user.name }}" {{ else }} "{{ .First.initiator.user.id }}" {{ end }}
Была выполнена команда: "{{ .First.initiator.command.executed}}"
Окружение, из которого выполнялась команда: {{ if .First.initiator.process.parent.path.original }} "{{ .First.initiator.process.parent.path.original}}". {{ else }} "{{ .First.observer.service.name}}".
{{ end }}]], risk_level = 7.0, asset_ip = logline:get_asset_data("observer.host.ip"), asset_hostname = logline:get_asset_data("observer.host.hostname"), asset_fqdn = logline:get_asset_data("observer.host.fqdn"), asset_mac = logline:get_asset_data(""), create_incident = true, incident_group = "", assign_to_customer = false, incident_identifier = "", logs = matchedData.loglines, mitre = {"T1037.004"}, trim_logs = 20})
	return true
end

local pattern1 = {{field = "initiator.command.executed", values = {"/usr/bin/cp /etc/rc.common /etc/rc.common.original"}, count = 1}, {field = "initiator.command.executed", values = {"/usr/bin/tee /etc/rc.common"}, count = 1}, {field = "initiator.command.executed", values = {"/usr/bin/tee -a /etc/rc.common", }, count = 1}, {field = "initiator.command.executed", values = {"/usr/bin/chmod +x /etc/rc.common"}, count = 1}}

local pattern2 = {{field = "initiator.command.executed", values = {"/usr/bin/touch /etc/rc.local"}, count = 1}, {field = "initiator.command.executed", values = {"/usr/bin/tee /etc/rc.local"}, count = 1}, {field = "initiator.command.executed", values = {"/usr/bin/tee -a /etc/rc.local", }, count = 1}, {field = "initiator.command.executed", values = {"/usr/bin/chmod +x /etc/rc.local"}, count = 1}}

grouper1 = grouper.new_pattern_matcher({"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}, {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}, {"@timestamp"}, pattern1, "@timestamp,RFC3339", "1m", on_matched)

grouper2 = grouper.new_pattern_matcher({"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}, {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}, {"@timestamp"}, pattern2, "@timestamp,RFC3339", "1m", on_matched)

1 -- /usr/bin/cp /etc/rc.local /etc/rc.local.original
2 -- /usr/bin/tee /etc/rc.local
3 -- /usr/bin/tee -a /etc/rc.local
