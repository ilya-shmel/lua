-- Шаблон алерта
local template = [[
{{ .Meta.title }}.

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
local grouped_time_field = "@timestamp,RFC3339"
local grouped_by1 = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "event.rule.description", "target.image.name"}
local aggregated_by1 = {"initiator.command.executed"}
local grouped_by2 = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "observer.process.id"}
local aggregated_by2 = {"observer.event.id"}

-- Регулярные выражения
local threats = {{
    pattern = [=[(?:^|\s+|"|'|\\)net1?\s+accounts[\\\s"'\:;)]]=],
    name = "Получение информации о парольной локальной политике через net accounts",
    risk = 6.0,
    mitre = {"T1021"}
}, {
    pattern = [=[(?:^|\s+|"|'|\/)get-(?:passpol|domainpolicy|adreplaccount)(?:[\\\s"'\:;.)]|$)]=],
    name = "Использование утилит PowerView/PowerSploit/PoshC2/DSInternals для получения парольной политики",
    risk = 8.5,
    mitre = {"T1021"}
}, {
    pattern = [=[(?:^|\s+|"|'|\/|\()get-(?:addefaultdomainpasswordpolicy|aduser)(?:[\\\s"'\:;)]|$)([^,]+(\s?(cannotchange)?password(?:lastset|neverexpires|expired|notrequired|$),?)+)?]=],
    name = "Получение парольной политики домена через Active Directory PowerShell",
    risk = 6.5,
    mitre = {"T1021"}
}, {
    pattern = [=[(?:^|\s+|"|'|\\)secedit(\.exe)?[\\\s"'\:;)](\s+)?\/export([\s\S]*)?securitypolicy]=],
    name = "Экспорт локальной политики безопасности через secedit",
    risk = 7.0,
    mitre = {"T1021"}
}, {
    pattern = [=[(?:^|\s+|"|'|\\)wmic\s+useraccount\s+get([\s\S]*)?password[\\\s"'\:;)]]=],
    name = "Запрос параметров паролей пользователей через WMIC",
    risk = 6.5,
    mitre = {"T1021", "T1087.001"}
}}

-- Функция алерта
local function alert_function(events, meta)
    alert({
        template = template,
        meta = meta,
        risk_level = meta.risk, 
        asset_ip = meta.ip,
        asset_hostname = meta.hostname,
        asset_fqdn = meta.fqdn,
        asset_mac = "",
        create_incident = true,
        incident_group = "",
        assign_to_customer = false,
        incident_identifier = "",
        logs = events,
        mitre = meta.mitre,
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
    
    for _, pattern in ipairs(threats) do
        if cmd_lower:search(pattern.pattern) then
            return true, pattern.name, pattern.risk, pattern.mitre
        end
    end
    
    return false
end

-- Функция обработки логлайна
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")

    if compare(event_id, "==", 4103) then
        grouper2:feed(logline)
    else
        local command_executed = logline:gets("initiator.command.executed")
        local is_password, title, risk, mitre = analyze(command_executed)

        if is_password then
            set_field_value(logline, "event.rule.description", title)
            set_field_value(logline, "event.application.risk", risk)
            set_field_value(logline, "mitre.technique", mitre)
            
            if compare(event_id, "==", 4104) then
                grouper2:feed(logline)
            else
                grouper1:feed(logline)
            end
        end
    end
end

-- Функция группера #1
function on_grouped1(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local commands = {}
    local first_event = events[1]
        
    if unique_events > 0 then
        for _, event in ipairs(events) do
            table.insert(commands, event:gets("initiator.command.executed"))
        end
        
        local meta = {
            user=first_event:gets("initiator.user.name"),
            command=string_cut(table.concat(commands, "; ")),
            path=first_event:gets("target.process.path.full"),
            program=first_event:gets("target.image.name"),
            parent=first_event:gets("initiator.process.parent.path.original"),
            title=first_event:gets("event.rule.description"),
            risk=first_event:gets("event.application.risk"),
            mitre=first_event:gets("mitre.technique"),
            ip=first_event:gets("observer.host.ip"),
            hostname=first_event:gets("observer.host.hostname"),
            fqdn=first_event:gets("observer.host.fqdn")
        }

        alert_function(events, meta)
        grouper1:clear()
    end
end

-- Функция группера #2
function on_grouped2(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_scriptblock, log_module

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")

            if compare(event_id, "==", "4104") then
                log_scriptblock = event
            else
                log_module = event
            end
        end

        if log_scriptblock and log_module then
            local meta = {
                user=log_module:gets("initiator.user.name"),
                command=string_cut(log_scriptblock:gets("initiator.command.executed")),
                path=log_module:gets("observer.service.name"),
                program=log_module:gets("initiator.process.command"),
                parent=log_module:gets("initiator.shell.name"),
                title=log_scriptblock:gets("event.rule.description"),
                risk=log_scriptblock:gets("event.application.risk"),
                mitre=log_scriptblock:gets("mitre.technique"),
                ip=log_scriptblock:gets("observer.host.ip"),
                hostname=log_scriptblock:gets("observer.host.hostname"),
                fqdn=log_scriptblock:gets("observer.host.fqdn")
            }
            alert_function(events, meta)
            grouper2:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by1, aggregated_by1, grouped_time_field, detection_window, on_grouped1)
grouper2 = grouper.new(grouped_by2, aggregated_by2, grouped_time_field, detection_window, on_grouped2)