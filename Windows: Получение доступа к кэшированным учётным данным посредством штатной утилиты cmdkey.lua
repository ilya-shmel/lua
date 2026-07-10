-- Шаблон алерта
local template = [[
Обнаружено получение доступа к кэшированным учётным данным посредством штатной утилиты cmdkey.

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{ or .Meta.ip "IP-адрес не определён" }}
Узел: {{ or .Meta.hostname "Имя узла не определено" }}
FQDN: {{ or .Meta.fqdn "FQDN узла не определено" }}

ИНИЦИАТОР:
Пользователь: {{ or .Meta.user "Пользователь не определён"}}

ВЫПОЛНЕННАЯ КОМАНДА:
{{ .Meta.command }}
Имя программы: {{ .Meta.program }}
Процесс/Путь к исполняемому файлу: {{ .Meta.path }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local suspicious_pattern = [[(?:^|\/|\s+|"|'|\()cmdkey(\.exe)?\s+\/?list]]

-- Функция алерта
local function alert_function(events, ip, hostname, fqdn, user, cmd, program, path)
    alert({
        template = template,
        meta = {
            user=user,
            command=cmd,
            path=path,
            program=program,
            service=service,
            ip=ip,
            hostname=hostname,
            fqdn=fqdn
            },
        risk_level = 9.0, 
        asset_ip = ip,
        asset_hostname = hostname,
        asset_fqdn = fqdn,
        asset_mac = "",
        create_incident = true,
        incident_group = "",
        assign_to_customer = false,
        incident_identifier = "",
        logs = events,
        mitre = {"T1003.005"},
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
    local command_executed = logline:gets("initiator.command.executed"):lower()
    
    if command_executed:search(suspicious_pattern) then
        grouper1:feed(logline)
    end
end

-- Функция группера #1
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local first_event = events[1]
    
    if #events > 0 then
        local initiator_name = first_event:gets("initiator.user.name")  
        local host_ip = first_event:get("observer.host.ip")
        local host_name = first_event:gets("observer.host.hostname")
        local host_fqdn = first_event:gets("observer.host.fqdn")
        local program_name = first_event:gets("target.image.name")
        local command_executed = string_cut(first_event:gets("initiator.command.executed"))
        local process_path = first_event:get("target.process.path.full")

        alert_function(events, host_ip, host_name, host_fqdn, initiator_name, command_executed, program_name, process_path)
        grouper1:clear()
        

    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)

