function on_logline(logline)
	if substr(logline:get("event.context.raw", ""):lower(), ("Command Name = Enable-PSRemoting"):lower()) or (search(logline:get("initiator.command.executed", ""), "\s+{[\w\s_+-]{0,255}}") and search(logline:get("initiator.command.executed", ""), "\s+\$env:\w+\s+") and contains({("-ComputerName"):lower(), ("-ScriptBlock"):lower()}, logline:get("initiator.command.executed", ""):lower(), "sub")) or (not substr(logline:get("target.user.name", ""), "$") and compare(logline:get("initiator.auth.logon.type", ""), EQ, 3) and search(logline:get("target.user.id", ""), "S(-\d){2}(-\d+){1,5}") and compare(logline:get("event.auth.method.name", ""), EQ | IGNORE_CASE, "NTLM") and substr(logline:get("target.auth.process.name", ""):lower(), ("NtLmSsp"):lower()) and compare(logline:get("initiator.user.id", ""), EQ, "S-1-0-0") and compare(logline:get("initiator.user.name", ""), EQ, "-")) then
		grouper1:feed(logline)
	end
end
function on_grouped(grouped)
	local logline = grouped.aggregatedData.loglines[1]
	if grouped.aggregatedData.aggregated.total >= 1 then
		alert({template = [[Подозрение на эксплуатацию WinRM.

На узле: "{{ .First.observer.host.ip }}" - "{{ .First.observer.host.hostname }}",
Пользователем: {{ if .First.initiator.user.name }} "{{ .First.initiator.user.name }}" {{ else }} "{{ .First.initiator.user.id }}" {{ end }}
Была выполнена команда: {{ if .First.initiator.command.executed}} "{{ .First.initiator.command.executed}}" {{ else }} "{{ .First.event.context.raw }}" {{ end }}
Окружение, из которого выполнялась команда: {{ if .First.initiator.process.parent.path.original }} "{{ .First.initiator.process.parent.path.original}}". {{ else }} "{{ .First.observer.service.name}}".
{{ end }}]], risk_level = 7.0, asset_ip = logline:get_asset_data("observer.host.ip"), asset_hostname = logline:get_asset_data("observer.host.hostname"), asset_fqdn = logline:get_asset_data("observer.host.fqdn"), asset_mac = logline:get_asset_data(""), create_incident = true, incident_group = "", assign_to_customer = false, incident_identifier = "", logs = grouped.aggregatedData.loglines, mitre = {"T1021.006"}, trim_logs = 5})
		grouper1:clear()
	end
end
grouper1 = grouper.new({"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}, {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}, "@timestamp,RFC3339", "5m", on_grouped)
