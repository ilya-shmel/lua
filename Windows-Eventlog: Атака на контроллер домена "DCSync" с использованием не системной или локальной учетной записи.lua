-- Шаблон алерта
local template = [[
Обнаружена атака на контроллер домена "DCSync".

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{ or .Meta.ip "IP-адрес не определён" }}
Узел: {{ or .Meta.hostname "Имя узла не определено" }}
FQDN: {{ or .Meta.fqdn "FQDN узла не определено" }}

ИНИЦИАТОР:
Пользователь: {{ or .Meta.user "Пользователь не определён"}}

ВЫПОЛНЕННАЯ КОМАНДА:
{{ .Meta.command }}
Имя программы: {{ .Meta.program }}
Процесс/Путь к иcполняемому файлу: {{ .Meta.path }}
Целевой пользователь: {{ .Meta.target_user }}
Целевой домен: {{ .Meta.target_domain }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "initiator.auth.logon.id"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local dcsync_pattern = [[(?:^|\/|\s+|"|'|\()mimikatz(\.exe)?\s+['"]?lsadump::dcsync\s+\/domain:[^\/]*\/user:[^\s]*['"]?]]

-- Функция алерта
local function alert_function(events, ip, hostname, fqdn, user, cmd, program, path, target_user, target_domain)
    alert({
        template = template,
        meta = {
            user=user,
            command=cmd,
            path=path,
            program=program,
            target_user=target_user,
            target_domain=target_domain,
            ip=ip,
            hostname=hostname,
            fqdn=fqdn
            },
        risk_level = 10.0, 
        asset_ip = ip,
        asset_hostname = hostname,
        asset_fqdn = fqdn,
        asset_mac = "",
        create_incident = true,
        incident_group = "",
        assign_to_customer = false,
        incident_identifier = "",
        logs = events,
        mitre = {"T1003.006"},
        trim_logs = 10
        }
     )
end

-- Функция сокращения строки для алерта
local function string_cut(cmd)
    if #cmd > 128 then
        cmd = cmd:sub(1, 128).. "... "
    end

    return cmd
end

-- Функция обработки логлайна
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")
    
    if compare(event_id, "==", "4688") then
        local command_executed = logline:gets("initiator.command.executed"):lower()

        if command_executed:search(dcsync_pattern) then
            grouper1:feed(logline)
        end
    else
        grouper1:feed(logline)
    end
end

-- Функция группера #1
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec, log_ad_event
    
    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")

            if compare(event_id, "==", "4688") then
                log_exec = event
            else
                log_ad_event = event
            end
        end

        if log_exec and log_ad_event then
            local initiator_name = log_exec:gets("initiator.user.name")  
            local host_ip = log_exec:get("observer.host.ip")
            local host_name = log_exec:gets("observer.host.hostname")
            local host_fqdn = log_exec:gets("observer.host.fqdn")
            local program_name = log_exec:gets("target.image.name")
            local command_executed = string_cut(log_exec:gets("initiator.command.executed"))
            local process_path = log_exec:gets("target.process.path.full")
            local target_domain = command_executed:match("/domain:([^%s/]+)%s+")
            local target_user = command_executed:match("/user:([^@]+)@[%s%S]*")
 
            alert_function(events, host_ip, host_name, host_fqdn, initiator_name, command_executed, program_name, process_path, target_user, target_domain)
            grouper1:clear()
        end

    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)

