local detection_window = "1m"
local create_incident = true

local grouped_time_field = "@timestamp,RFC3339"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}

local service_query_patterns = {"^.*[Ss][Ee][Rr][Vv][Ii][Cc][Ee]%s+%-[Ee].*$",
                                "^.*[Ss][Ee][Rr][Vv][Ii][Cc][Ee]%s+%-%-[Ss][Tt][Aa][Tt][Uu][Ss]%-[Aa][Ll][Ll].*$",
                                "^.*[Ss][Ee][Rr][Vv][Ii][Cc][Ee]%s+[%w%-_.]+%s+[Ss][Tt][Aa][Tt][Uu][Ss].*$",
                                "^.*[Ss][Yy][Ss][Tt][Ee][Mm][Cc][Tt][Ll]%s+[Ss][Hh][Oo][Ww].*$",
                                "^.*[Ss][Yy][Ss][Tt][Ee][Mm][Cc][Tt][Ll]%s+[Ii][Ss]%-[Aa][Cc][Tt][Ii][Vv][Ee].*$",
                                "^.*[Ss][Yy][Ss][Tt][Ee][Mm][Cc][Tt][Ll]%s+[Ii][Ss]%-[Ee][Nn][Aa][Bb][Ll][Ee][Dd].*$",
                                "^.*[Ss][Yy][Ss][Tt][Ee][Mm][Cc][Tt][Ll]%s+.*%-%-[Tt][Yy][Pp][Ee]=.*[Ss][Ee][Rr][Vv][Ii][Cc][Ee].*$",
                                "^.*[Jj][Oo][Uu][Rr][Nn][Aa][Ll][Cc][Tt][Ll]%s+%-[Uu].*$",
                                "^.*[Ii][Nn][Ii][Tt][Cc][Tt][Ll]%s+[Ll][Ii][Ss][Tt].*$",
                                "^.*[Ii][Nn][Ii][Tt][Cc][Tt][Ll]%s+[Ss][Tt][Aa][Tt][Uu][Ss].*$",
                                "^.*[Ss][Yy][Ss][Tt][Ee][Mm][Dd]%-[Aa][Nn][Aa][Ll][Yy][Zz][Ee].*$",
                                "^.*[Cc][Hh][Kk][Cc][Oo][Nn][Ff][Ii][Gg].*$"}


local command_pattens = {
    "service\\s+([\\w\\.-]+\\s+status)?-{1,2}(?:e|status-all)",
    "systemctl\\s+(?:show|is-(?:active|enabled)|--type=service)",
    "(?:journal|init)ctl\\s+(:?-u|list|status)",
    "(?:systemd-analyze|chkconfig)"
}
local template = [[Обнаружен поиск информации о сервисах

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{ if .First.observer.host.ip }}"{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
Узел: {{ if .First.observer.host.hostname }}"{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}

ИНИЦИАТОР:
Пользователь: {{.Meta.user_name}}
UID: {{.Meta.user_id}}
Процесс: {{.Meta.process_name}}
Путь процесса: {{.Meta.process_path}}

ДЕТАЛИ КОМАНДЫ:
Выполненная команда: {{.Meta.command_executed}}

АНАЛИЗ:
Описание: Обнаружено выполнение команды для перечисления или проверки статуса сервисов системы.]]

local function match_service_query_pattern(command)
    for _, pattern in ipairs(service_query_patterns) do
        if command:match(pattern) then
            return true
        end
    end

    return false
end

local function analyze_service_query(command)
    local cmd_lower = command:lower()

    for _, pattern in pairs(command_patterns) do
        is_command = cmd_string:search(pattern)
        if is_command then
            return is_command
        end
    end
end

function on_logline(logline)
    local event_type = logline:gets("observer.event.type")

    if event_type == "EXECVE" or event_type == "PROCTITLE" then
        local command_executed = logline:gets("initiator.command.executed")

        if command_executed and match_service_query_pattern(command_executed) then
            grouper1:feed(logline)
        end
    elseif event_type == "SYSCALL" then
        grouper1:feed(logline)
    end
end

function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec = nil
    local log_sys = nil

    for _, event in ipairs(events) do
        local event_type = event:gets("observer.event.type")

        if event_type == "SYSCALL" then
            log_sys = event
        elseif event_type == "EXECVE" or event_type == "PROCTITLE" then
            log_exec = event
        end
    end

    if log_sys and log_exec then
        if unique_events > 1 then
            local user_name = log_sys:gets("initiator.user.name")
            local user_id = log_sys:gets("initiator.user.id")
            local process_path = log_sys:gets("initiator.process.path.full")
            local process_name = log_sys:gets("initiator.process.path.name")
            local command_executed = log_exec:gets("initiator.command.executed")
            local host_ip = log_exec:gets("observer.host.ip")
            local host_hostname = log_exec:gets("observer.host.hostname")
            local host_fqdn = log_exec:gets("observer.host.fqdn", host_hostname)

            if #command_executed > 128 then
                command = command:sub(1, 128) .. "..."
            end
            local meta = {
                user_name = user_name,
                user_id = user_id,
                process_name = process_name,
                process_path = process_path,
                command_executed = command_executed,
                total_events = tostring(total)
            }

            alert({
                template = template,
                meta = meta,
                risk_level = 5.0,
                asset_ip = host_ip,
                asset_hostname = host_hostname,
                asset_fqdn = host_fqdn,
                create_incident = create_incident,
                assign_to_customer = false,
                logs = events,
                trim_logs = 10,
                mitre = {"T1007"}
            })
            grouper1:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)