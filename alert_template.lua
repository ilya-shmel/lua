alert({
    template = template,
    meta = {
        user_name=log_sys:gets("initiator.user.name"),
        header=header,
        command=command
        },
    risk_level = 7.0, 
    asset_ip = log_exec:get_asset_data("observer.host.ip"),
    asset_hostname = log_exec:get_asset_data("observer.host.hostname"),
    asset_fqdn = log_exec:get_asset_data("observer.host.fqdn"),
    asset_mac = log_exec:get_asset_data(""),
    create_incident = true,
    incident_group = "",
    assign_to_customer = false,
    incident_identifier = "",
    logs = grouped.aggregatedData.loglines,
    mitre = {"T1562.001"},
    trim_logs = 10
    }
)