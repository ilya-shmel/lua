-- Шаблон алерта
local template = [[
Подозрение на копирование учётных данных с помощью утилиты rundll32.exe и библиотеки keymgr.

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
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "initiator.command.executed"}
local aggregated_by = {"observer.process.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local mgr_pattern = [[(?:^|[\\\s"'(])rundll32(?:\.exe)?[\\\s"'\)]?\s+((krshow)?keymgr,?)+]]

-- Функция алерта
local function alert_function(events, ip, hostname, fqdn, user, cmd, program, path)
    alert({
        template = template,
        meta = {
            user=user,
            command=cmd,
            path=path,
            program=program,
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
        mitre = {"T1003.004"},
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
    
    if command_executed:search(mgr_pattern) then
        grouper1:feed(logline)
    end
end

-- Функция группера #1
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local first_event = events[1]
    
    if first_event  then
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