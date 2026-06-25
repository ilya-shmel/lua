local template = [[
    Обнаружена сетевая разведка.
    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]

local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

local process_pattern =
    "(?i)(?:^|\\/|\\\\|\\\"|\\'|\\s+)(?:nmap|zmap|masscan|arp\\-scan|sslscan|netdiscover|arp\\s+\\-a|ip\\s+neigh\\s+show|nikto|dirb|nc|netcat|ping\\d?|hping\\d?|fping\\d?|traceroute|netstat|ss|knock)(?:\\s+|$|\\\"|\\')"
local whitelist_pattern = "(?i)(?:\\.psf\\.gz|consolefonts)"

local function analyze(cmd)
    if cmd:search(whitelist_pattern) then
        return false
    end
    return cmd:search(process_pattern)
end

function on_logline(logline)
    local event_type = logline:gets("observer.event.type", "")

    if event_type == "EXECVE" or event_type == "PROCTITLE" then
        local command = logline:gets("initiator.command.executed", "")
        if command ~= "" and analyze(command) then
            grouper1:feed(logline)
        end
    elseif event_type == "SYSCALL" then
        grouper1:feed(logline)
    end
end

function on_grouped(grouped)
    if grouped.aggregatedData.aggregated.total >= 1 then
        local log_sys = nil
        local log_exec = nil

        for _, event in ipairs(grouped.aggregatedData.loglines) do
            local ev_type = event:gets("observer.event.type", "")
            if ev_type == "SYSCALL" then
                log_sys = event
            elseif ev_type == "EXECVE" or ev_type == "PROCTITLE" then
                log_exec = event
            end
        end

        if log_sys and log_exec then
            local command = log_exec:gets("initiator.command.executed", "")

            if command ~= "" and analyze(command) then
                alert({
                    template = template,
                    meta = {
                        user_name = log_sys:gets("initiator.user.name", "Не определен"),
                        command = command,
                        command_path = log_sys:gets("initiator.process.path.full", "Не определен")
                    },
                    risk_level = 9.0,
                    asset_ip = log_exec:get_asset_data("observer.host.ip"),
                    asset_hostname = log_exec:get_asset_data("observer.host.hostname"),
                    asset_fqdn = log_exec:get_asset_data("observer.host.fqdn"),
                    asset_mac = "",
                    create_incident = true,
                    incident_group = "Discovery",
                    assign_to_customer = false,
                    incident_identifier = log_exec:gets("observer.host.hostname", "unknown") .. "_network_recon",
                    logs = grouped.aggregatedData.loglines,
                    mitre = {"T1046"},
                    trim_logs = 10
                })
            end
        end

        grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)