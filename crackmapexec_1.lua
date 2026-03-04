function on_grouped(grouped)
	local logline = grouped.aggregatedData.loglines[1]
	if grouped.aggregatedData.aggreg.total >= 1 then
		-- Check IP
		local user_name = logline:get_asset_data("target.user.name")
		local host_hostname = logline:get_asset_data("observer.host.hostname")
		
		local host_info
		if host_ip and host_ip ~= "" then
			host_info = host_ip .. " - " .. host_hostname
		else
			host_info = host_hostname
		end
		
		alert({
			template = [[На ПК зафиксирован запуск утилиты crackmapexec.
На хосте: "{{ .host_info }}",
Пользователем: "{{ .First.target.user.name }}"
Была выполнена команда: "{{ .First.initiator.command.executed}}"
Окружение, из которого выполнялась команда: "{{ .First.initiator.process.parent.path.original}}".
]],
			risk_level = 7.0,
			asset_ip = logline:get_asset_data("reportchain.relay.host.ip"),
			asset_hostname = logline:get_asset_data("observer.host.hostname"),
			asset_fqdn = logline:get_asset_data("observer.host.hostname"),
			asset_mac = logline:get_asset_data(""),
			create_incident = true,
			incident_group = "",
			assign_to_customer = false,
			incident_identifier = "",
			logs = grouped.aggregatedData.loglines,
			mitre = {"T1550.002"},
			trim_logs = 5,
			vars = {host_info = host_info} -- Send var to remplate
		})
		
		grouper1:clear()
	end
end
