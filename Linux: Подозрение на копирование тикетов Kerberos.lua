local template = [[
Подозрение на копирование тикетов Kerberos.


ЦЕЛЕВОЙ УЗЕЛ:
IP: {{.Meta.observer_ip}}
Хост: {{.Meta.observer_hostname}}
FQDN: {{.Meta.observer_fqdn}}


ИНИЦИАТОР:
Пользователь: {{.Meta.user_name}}
UID: {{.Meta.user_id}}
Процесс: {{.Meta.process_path}}


КОМАНДА:
{{.Meta.command}}
]]

local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

local kerberos_pattern = "krb5cc|klist.*-c|KRB5CCNAME|krb5\\.conf"
local command_pattern = "(?:^|\\s+|\\/|\\\\|\"|\')(?:cp|mv|cat|tar|zip|gzip|scp|rsync|xxd|hexdump|strings|nc|curl|wget|find|ls|locate|netcat)"

local function analyze(cmd)
    return cmd:search(command_pattern) and cmd:search(kerberos_pattern)
end

function on_logline(logline)
    local event_type = logline:gets("observer.event.type")

    if event_type == "EXECVE" or event_type == "PROCTITLE" then
        local command = logline:get("initiator.command.executed")
        if analyze(command) then
            grouper1:feed(logline)
        end
    elseif event_type == "SYSCALL" then
        grouper1:feed(logline)
    end
end

function on_grouped(grouped)
    if grouped.aggregatedData.unique.total > 1 then
        local log_exec = nil
        local log_sys = nil

        for _, log in ipairs(grouped.aggregatedData.loglines) do
            if log:gets("observer.event.type") == "SYSCALL" then
                log_sys = log
            else
                log_exec = log
            end
        end

        if log_exec and log_sys then
            alert({
                template = template,
                meta = {
                    observer_ip = log_exec:gets("observer.host.ip", "Не определено"),
                    observer_hostname = log_exec:gets("observer.host.hostname", "Не определено"),
                    observer_fqdn = log_exec:gets("observer.host.fqdn", "Не определено"),
                    user_name = log_sys:gets("initiator.user.name", "Не определено"),
                    user_id = log_sys:gets("initiator.user.id", "Не определено"),
                    process_path = log_sys:gets("initiator.process.path.full", "Не определено"),
                    command = log_exec:gets("initiator.command.executed", "Не определено")
                },
                risk_level = 8.0,
                asset_ip = log_exec:get_asset_data("observer.host.ip"),
                asset_hostname = log_exec:get_asset_data("observer.host.hostname"),
                asset_fqdn = log_exec:get_asset_data("observer.host.fqdn"),
                asset_mac = "",
                create_incident = true,
                incident_group = "Credential Access",
                assign_to_customer = false,
                incident_identifier = "",
                logs = grouped.aggregatedData.loglines,
                mitre = {"T1558.002", "T1555.001"},
                trim_logs = 10
            })
            grouper1:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)