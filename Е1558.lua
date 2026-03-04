function on_logline(logline)
	if substr(logline:get("initiator.command.executed", ""), "grep krb") then
		alert({template = [[Подозрение на копирование тикетов Kerberos.

                            На узле: "{{ .First.observer.host.ip }}" - "{{ .First.observer.host.hostname }}",
                            Пользователем: {{ if .First.initiator.user.name }} "{{ .First.initiator.user.name }}" {{ else }} "{{ .First.initiator.user.id }}" {{ end }}
                            Была выполнена команда: "{{ .First.initiator.command.executed}}"
                            Окружение, из которого выполнялась команда: {{ if .First.initiator.process.parent.path.original }} "{{ .First.initiator.process.parent.path.original}}". {{ else }} "{{ .First.observer.service.name}}".
                            {{ end }}]], 
        risk_level = 5.0,
        asset_ip = logline:get_asset_data("observer.host.ip"),
        asset_hostname = logline:get_asset_data("observer.host.hostname"),
        asset_fqdn = logline:get_asset_data("observer.host.fqdn"),
        asset_mac = logline:get_asset_data(""),
        create_incident = true,
        incident_group = "",
        assign_to_customer = false,
        incident_identifier = "",
        logs = {logline},
        mitre = {"T1558"},
        trim_logs = 5
        })
	end
end
