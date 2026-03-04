function on_logline(logline)
	if contains({
        ("get-ptaspylog"):lower(),
        ("install-ptaspy"):lower(),
        ("ptaspy"):lower(),
        ("aadintptaspy"):lower(),
        ("get-aadintptaspylog"):lower(),
        ("-decodepasswords"):lower()},
        logline:get("initiator.command.executed", ""):lower(), "sub") then
		
        local short_cmd = logline:get("initiator.command.executed", "")
        
        if #short_cmd > 200 then
            short_cmd = short_cmd:sub(1, 200) .. "..."
            logline.short_cmd = short_cmd
        end
        
        local log_copy = {
            initiator = {
                user = {
                    name = logline.initiator.user and logline.initiator.user.name,
                    id = logline.initiator.user and logline.initiator.user.id
                },
                command = {
                    executed = logline.initiator.command and logline.initiator.command.executed
                },
                process = {
                    parent = {
                        path = {
                            original = (logline.initiator.process and logline.initiator.process.parent and logline.initiator.process.parent.path) and logline.initiator.process.parent.path.original
                        }
                    }
                }
            },
            observer = {
                host = {
                    ip = logline.observer.host and logline.observer.host.ip,
                    hostname = logline.observer.host and logline.observer.host.hostname
                },
                service = {
                    name = logline.observer.service and logline.observer.service.name
                }
            },
            short_cmd = short_cmd
        }


        alert({
            template = [[Подозрение на сбор реквизитов доступа с помощью AADInternal.

                       На узле: "{{ .First.observer.host.ip }}" - "{{ .First.observer.host.hostname }}",
                       Пользователем: {{ if .First.initiator.user.name }} "{{ .First.initiator.user.name }}" {{ else }} "{{ .First.initiator.user.id }}" {{ end }}
                       Была выполнена команда: {{ if .First.short_cmd }} "{{ .First.short_cmd }}". {{ else }} "{{ .First.initiator.command.executed }}".
                       Окружение, из которого выполнялась команда: {{ if .First.initiator.process.parent.path.original }} "{{ .First.initiator.process.parent.path.original}}". {{ else }} "{{ .First.observer.service.name}}".
                       {{ end }}]],
            risk_level = 8.0,
            asset_ip = logline:get_asset_data("observer.host.ip"),
            asset_hostname = logline:get_asset_data("observer.host.hostname"),
            asset_fqdn = logline:get_asset_data("observer.host.fqdn"),
            asset_mac = logline:get_asset_data(""),
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "",
            logs = {logline},
            mitre = {"T1556.007"},
            trim_logs = 5})
	end
end
