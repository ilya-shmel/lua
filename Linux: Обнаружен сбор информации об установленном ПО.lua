local template = [[
Обнаружен сбор информации об установленном ПО

ИСТОЧНИК СБОРА:
IP: {{.Meta.source_ip}}
Узел: {{.Meta.hostname}}
FQDN: {{.Meta.fqdn}}

ДЕТАЛИ ОПЕРАЦИИ:
Пользователь: {{.Meta.user_name}}
Команда: {{.Meta.command}}
]]

local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

local prefix = "(?:^|\\/|\\\\|\"|'|\\s+)"
local software_enumeration_patterns = {
    prefix .."(?:dpkg(-query)?|rpm|pacman|pip|npm|gem|composer)\\s+(-{1,2})?(?:l(s)?(ist)?|w|show|qa|query|all|q|search)",
    prefix .."apt\\s+(?:list|cache)\\s+(?:--all-versions|--installed)",
    prefix .."(?:yum|flatpak|brew|snap)\\s+(?:list|info)",
    prefix .."systemctl\\s+list-units\\s+--(?:all|type=service)",
    prefix .."ps\\s+(?:-ef|aux|full)\\s+(?:\\||grep)",
    prefix .."(?:netstat|ss)\\s+-(?:tln(?:p|a)|anp)",
    prefix .."(?:lsof|uname|lsb_release)\\s+-(?:i|p|a|r)",
    prefix .."cat\\s+/etc/(?:os|lsb|system|redhat)-release",
    prefix .."file\\s+/bin/(?:ls|(ba)?sh)"
}

local false_positive_pattern =
    prefix .."(?:apt-cache|apt-get|yum-cron|systemd|ansible|puppet|chef|salt|docker|lxc|snap|flatpak)"

local function clean(cmd)
    local c = string.gsub(cmd, "%z", " ")
    c = string.gsub(c, "%s+", " ")
    return string.match(c, "^%s*(.-)%s*$") or c
end

local function is_valid_ip(ip)
    return ip:match("^%d+%.%d+%.%d+%.%d+$") or ip:match("^[0-9a-fA-F:]+$")
end

local function analyze_command(cmd)
    if cmd:search(false_positive_pattern) then
        return nil
    end

    for _, pattern in ipairs(software_enumeration_patterns) do
        if cmd:search(pattern) then
            return true
        end
    end

    return nil
end

function on_logline(logline)
    local event_type = logline:gets("observer.event.type")

    if event_type == "EXECVE" or event_type == "PROCTITLE" then
        local command = logline:gets("initiator.command.executed")
        if command and command ~= "" and analyze_command(command) then
            grouper1:feed(logline)
        end
    elseif event_type == "SYSCALL" then
        grouper1:feed(logline)
    end
end

function on_grouped(grouped)
    if grouped.aggregatedData.unique.total < 2 then
        return
    end

    local log_exec = nil
    local log_sys = nil

    for _, log in ipairs(grouped.aggregatedData.loglines) do
        local etype = log:gets("observer.event.type")
        if etype == "SYSCALL" then
            log_sys = log
        elseif etype == "EXECVE" or etype == "PROCTITLE" then
            log_exec = log
        end
    end

    if log_exec and log_sys then
      
        local command = clean(log_exec:gets("initiator.command.executed"))

        if not analyze_command(command) then
            return
        end

        local source_ip = log_exec:gets("observer.host.ip") or "Не определено"
        if not is_valid_ip(source_ip) then
            source_ip = log_exec:gets("reportchain.collector.host.ip") or "0.0.0.0"
        end

        local hostname = log_exec:gets("observer.host.hostname", "Не определено")
        local fqdn = log_exec:gets("observer.host.fqdn", hostname)
        local user_name = log_sys:gets("initiator.user.name", "Не определено")

        alert({
            template = template,
            meta = {
                source_ip = source_ip,
                hostname = hostname,
                fqdn = fqdn,
                user_name = user_name,
                command = command
            },
            risk_level = 5.5,
            asset_ip = source_ip,
            asset_hostname = hostname,
            asset_fqdn = fqdn,
            asset_mac = "",
            create_incident = true,
            incident_group = "Discovery",
            assign_to_customer = false,
            incident_identifier = "",
            logs = grouped.aggregatedData.loglines,
            mitre = {"T1518.001", "T1082", "T1007"},
            trim_logs = 10
        })
        grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)