local detection_windows = "5m"
local create_incident = true
local assign_to_customer = false
local risk_score = 9
local Threshold = 10
local grouped_by = { "initiator.host.ip", "target.user.name", "observer.host.ip", "observer.host.hostname", "observer.host.fqdn" }
local aggregated_by = grouped_by
local grouped_time_field = "@timestamp"
local template = [["На узле {{ .First.observer.host.ip }} зафиксирован успешный вход, под пользователем {{ .First.target.user.name }}, с хоста {{ .First.initiator.host.ip }}, после множественных неудачных попыток". 
Была выполнена команда: "{{ .First.initiator.process.command }}",окружение из которого выполнялась команда: "{{ .First.initiator.process.path.name}}", место выполнения: "{{ .First.initiator.command.path.original}}", пользователь, который выполнил команду: "{{ .First.initiator.user.name }}"."]]

function on_logline(logline) 
  grouper1:feed(logline)
end

function on_matched(grouped, matchedData)

  logline = matchedData.loglines[1]
  
  asset = get_fields_value(logline, {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"})
  meta = {}
  incident_identifier = get_field_value(logline, "target.group.name")
  
  alert({
      template = template,
      risk_level = risk_score,
      asset_ip = asset[1],
      asset_hostname = asset[2],0111
      asset_fqdn = asset[3],
      asset_mac = "",
      create_incident = create_incident,
      assign_to_customer = assign_to_customer,
      logs = matchedData.loglines,
      meta = meta,
      incident_identifier = incident_identifier
  })

  return true
end

pattern = {
    { field = "outcome.name", values = {"failure"}, count = Threshold },
    { field = "outcome.name", values = {"success"}, count = 1 },
}

grouper1 = grouper.new_pattern_matcher(
    -- groupBy fields
   grouped_by,
    -- aggregateBy fields, use if you need aggregatedData too
    {},
    -- sortOrder, NOTE: "@timestamp" is the essential first sort anyway and be filled automatically
    {"@timestamp"},
    -- pattern settings
    pattern,
    -- time field name with format followed after ','
    -- ex: "@timestamp", or "event.dt,2006-01-02 15:04:05", format by default is RFC3339Nano
    -- empty value means current timestamp will be used
    "@timestamp",
    -- window
    detection_windows,
    -- callback for each match found
    on_matched
)