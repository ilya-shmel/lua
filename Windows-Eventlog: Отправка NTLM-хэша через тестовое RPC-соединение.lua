-- Шаблон алерта
local template = [[
Обнаружена отправка NTLM-хэша через тестовое RPC-соединение.

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
Целевой узел: {{ .Meta.target_ip }}
Целевой порт: {{ .Meta.target_port }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "initiator.command.executed"}
local aggregated_by = {"initiator.process.command"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local rpc_pattern = [[(?:^|[\\\s"'(])rpcping(?:\.exe)?[\\\s"'\)]?\s+[\s\S]*?-u\s+ntlm]]
local ip_pattern = [[%s-s%s+(%d%d?%d?%.%d%d?%d?%.%d%d?%d?%.%d%d?%d?)%s]]
local port_pattern = [[%s-e%s+(%d+)%s]]

-- Функция алерта
local function alert_function(events, ip, hostname, fqdn, user, cmd, program, path, target_ip, target_port)
    alert({
        template = template,
        meta = {
            user=user,
            command=cmd,
            path=path,
            program=program,
            target_ip=target_ip,
            target_port=target_port,
            ip=ip,
            hostname=hostname,
            fqdn=fqdn
            },
        risk_level = 7.0, 
        asset_ip = ip,
        asset_hostname = hostname,
        asset_fqdn = fqdn,
        asset_mac = "",
        create_incident = true,
        incident_group = "",
        assign_to_customer = false,
        incident_identifier = "",
        logs = events,
        mitre = {"T1003"},
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
    
    if command_executed:search(rpc_pattern) then
        grouper1:feed(logline)
    end
end

-- Функция группера #1
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local first_event = events[1]
    
    if first_event then
        local initiator_name = first_event:gets("initiator.user.name")  
        local host_ip = first_event:gets("observer.host.ip")
        local host_name = first_event:gets("observer.host.hostname")
        local host_fqdn = first_event:gets("observer.host.fqdn")
        local program_name = first_event:gets("target.image.name")
        local command_executed = string_cut(first_event:gets("initiator.command.executed"))
        local process_path = first_event:get("target.process.path.full")
        local target_ip = command_executed:match(ip_pattern)
        local target_port = command_executed:match(port_pattern)

        alert_function(events, host_ip, host_name, host_fqdn, initiator_name, command_executed, program_name, process_path, target_ip, target_port)
        grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)