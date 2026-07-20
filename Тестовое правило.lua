blacklist = storage.new("blacklist_test")

-- Шаблон алерта
local template = [[
Тестовое правило.
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}
local aggregated_by = {"initiator.command.executed"}
local grouped_time_field = "@timestamp,RFC3339"

-- Функция алерта
local function alert_function(events, ip, hostname, fqdn, user, cmd)
    alert({
        template = template,
        meta = {
            user=user,
            command=cmd,
            ip=ip,
            hostname=hostname,
            fqdn=fqdn
            },
        risk_level = 4.0, 
        asset_ip = ip,
        asset_hostname = hostname,
        asset_fqdn = fqdn,
        asset_mac = "",
        create_incident = true,
        incident_group = "",
        assign_to_customer = false,
        incident_identifier = "",
        logs = events,
        mitre = {"T1003.004"},
        trim_logs = 10
        }
     )
end

-- Функция обработки логлайна
function on_logline(logline)
    local command_executed = logline:gets("initiator.command.executed")
    blacklist:set("ipconfig", "command", "ipconfig")
    blacklist:truncate()
    log("Number of elements: " .. tostring(blacklist:count()))
    values = blacklist:get_values("whoami")
    log("Values: " .. tostring(values.command))
    grouper1:feed(logline)
end

-- Функция группера #1
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    first_event = events[1]

    
    if #events > 0 then
        local initiator_name = first_event:gets("initiator.user.name")  
        local host_ip = first_event:get("observer.host.ip")
        local host_name = first_event:gets("observer.host.hostname")
        local host_fqdn = first_event:gets("observer.host.fqdn")
        local command_executed = first_event:gets("initiator.command.executed")
    
        alert_function(events, host_ip, host_name, host_fqdn, initiator_name, command_executed)
        grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)