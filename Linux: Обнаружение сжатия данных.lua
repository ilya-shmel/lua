local template = [[
Обнаружено сжатие данных на целевом узле.


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

local detection_window = "2m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

prefix = "(?:^|\\/|\"|\'|\\s+)"
local compression_patterns = {prefix.. "tar\\s+.*(?:-[a-z]*(?:z|j)|-c(?:z|j)(v)?f)",
                              prefix.. "(?:(?:g|b)?zip2?|(?:g|x|7)z)\\s+"
}

local suspicious_contexts = {"/tmp/", "/var/tmp/", "/dev/shm/", "/root/", ".ssh", "/etc/", "/var/log/"}

local exfiltration_indicators = {"(?:^|\\/|\\s+)(?:scp|sftp|ftp|nc|netcat|curl|wget)", "(?:^|\\/|\\s+)base64",
                                 "(?:^|\\/|\\s+)split\\s+-b", "\\|.*ssh", "\\|.*nc"}

local legitimate_tools = "(?:ansible|puppet|chef|salt|terraform|docker|systemd|boot)"

local function has_compression(cmd)
    for _, pattern in ipairs(compression_patterns) do
        if cmd:search(pattern) then
            return true
        end
    end
    return false
end

local function has_suspicious_context(cmd)
    for _, ctx in ipairs(suspicious_contexts) do
        if cmd:find(ctx, 1, true) then
            return true
        end
    end
    return false
end

local function has_exfiltration(cmd)
    for _, pattern in ipairs(exfiltration_indicators) do
        if cmd:search(pattern) then
            return true
        end
    end
    return false
end

function on_logline(logline)
    local event_type = logline:gets("observer.event.type")

    if event_type == "EXECVE" or event_type == "PROCTITLE" then
        local command = logline:gets("initiator.command.executed")
        if command and command ~= "" then
            if not command:search(legitimate_tools) and has_compression(command) then
                grouper1:feed(logline)
            end
        end
    else
        grouper1:feed(logline)
    end
end

function on_grouped(grouped)
    if grouped.aggregatedData.unique.total > 1 then
        local log_exec = nil
        local log_sys = nil

        for _, log in ipairs(grouped.aggregatedData.loglines) do
            local event_type = log:gets("observer.event.type")
            if event_type == "SYSCALL" then
                log_sys = log
            else
                log_exec = log
            end
        end

        if log_exec and log_sys then
            local command = log_exec:gets("initiator.command.executed")
            local risk = 6.0

            if has_suspicious_context(command) then
                risk = 7.5
            end

            if has_exfiltration(command) then
                risk = 9.0
            end

            alert({
                template = template,
                meta = {
                    observer_ip = log_exec:gets("observer.host.ip", "Не определено"),
                    observer_hostname = log_exec:gets("observer.host.hostname", "Не определено"),
                    observer_fqdn = log_exec:gets("observer.host.fqdn", "Не определено"),
                    user_name = log_sys:gets("initiator.user.name", "Не определено"),
                    user_id = log_sys:gets("initiator.user.id", "Не определено"),
                    process_path = log_sys:gets("initiator.process.path.full") or
                        log_sys:gets("initiator.process.path.name") or "Не определено",
                    command = command
                },
                risk_level = risk,
                asset_ip = log_exec:get_asset_data("observer.host.ip"),
                asset_hostname = log_exec:get_asset_data("observer.host.hostname"),
                asset_fqdn = log_exec:get_asset_data("observer.host.fqdn"),
                asset_mac = "",
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                logs = grouped.aggregatedData.loglines,
                mitre = {"T1560", "T1560.001", "T1560.002", "T1560.003", "T1041"},
                trim_logs = 10
            })
            grouper1:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)