-- Шаблон алерта
local template = [[
Подозрение на дамп DNS Active Directory.

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{ or .Meta.ip "IP-адрес не определён" }}
Узел: {{ or .Meta.hostname "Имя узла не определено" }}
FQDN: {{ or .Meta.fqdn "FQDN узла не определено" }}

ИНИЦИАТОР:
Пользователь: {{ or .Meta.user "Пользователь не определён"}}

ВЫПОЛНЕННАЯ КОМАНДА:
{{ .Meta.command }}
Имя программы: {{ .Meta.program }}
Путь к иcполняемому файлу: {{ .Meta.path }}
Процесс-инициатор: {{ .Meta.initiator_path }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "target.image.name"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local suspicious_patterns = {   
    PSH = {
        short_pattern = [[get\-]],
        main_pattern = [[(?:^|\\|\s+|"|'|\()get-dnsserver(?:zone|resourcerecord)(?:$|\\|\s+|"|'|\))]],
        name = "Подозрение на дамп DNS Active Directory с помощью командлетов PowerShell."
    },
    CMD = {
        short_pattern = [[(?:axfr|dns|\/zoneexport|-l)]],
        main_pattern = [[(?:^|\\|\s+|"|'|\()(?:nslookup|dig|ldapsearch|ldifde|csvde|powerview|crackmapexec|impacket|dnscmd|host)(\.exe)?(?:\\|\s+|"|'|\))[\s\S]*(?:axfr|dns(?:zone|record|node)|dns|\/zoneexport|-l)]],
        name = "Подозрение на дамп DNS Active Directory с помощью встроенных команд."
    },
    MALWARE = {
        short_pattern = [[(?:(adi)?dns(?:dump|cat|2tcp|recon|map)|iodine|hound|recon|fierce)]],
        main_pattern = [[(?:^|\/|\s+|"|'|\()(?:adidnsdump|dnscat|iodine|dns2tcp|bloodhound|sharphound|adrecon|fierce|dnsrecon|dnsmap)(?:\/|\s+|"|'|\))]],
        name = "Подозрение на дамп DNS Active Directory с помощью специальных команд."
    }                     
}

-- Функция алерта
local function alert_function(events, ip, hostname, fqdn, user, cmd, program, path, source_path)
    alert({
        template = template,
        meta = {
            user=user,
            command=cmd,
            path=path,
            program=program,
            initiator_path=source_path,
            ip=ip,
            hostname=hostname,
            fqdn=fqdn
            },
        risk_level = 5.0, 
        asset_ip = ip,
        asset_hostname = hostname,
        asset_fqdn = fqdn,
        asset_mac = "",
        create_incident = true,
        incident_group = "",
        assign_to_customer = false,
        incident_identifier = "",
        logs = events,
        mitre = {"T1003.006", "T1018"},
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

-- Функция анализа строки по регулярному выражению
local function analyze(cmd)
    local cmd_lower = cmd:lower()

    for _, pattern in pairs(suspicious_patterns) do
        if cmd_lower:search(pattern.short_pattern) then
            if cmd_lower:search(pattern.main_pattern) then
                local title = pattern.name
                return true, title
            end
        end
    end
    
    return false
end

-- Функция обработки логлайна
function on_logline(logline)
    local is_dns_dump, title
    local command_executed = logline:gets("initiator.command.executed")
    is_dns_dump, title = analyze(command_executed)

    if is_dns_dump then
        set_field_value(logline, "event.rule.description", title) 
        grouper1:feed(logline)
    end
end

-- Функция группера #1
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local log_exec = events[1]

    if log_exec then
        local initiator_name = log_exec:gets("initiator.user.name")  
        local host_ip = log_exec:gets("observer.host.ip")
        local host_name = log_exec:gets("observer.host.hostname")
        local host_fqdn = log_exec:gets("observer.host.fqdn")
        local program_name = log_exec:gets("target.image.name")
        local command_executed = string_cut(log_exec:gets("initiator.command.executed"))
        local process_path = log_exec:gets("target.process.path.full")
        local initiator_path = log_exec:gets("initiator.process.parent.path.original")
        
        alert_function(events, host_ip, host_name, host_fqdn, initiator_name, command_executed, program_name, process_path, initiator_path)
        grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)