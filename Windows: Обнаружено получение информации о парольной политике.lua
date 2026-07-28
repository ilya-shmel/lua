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
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "event.rule.description"}
local aggregated_by = {"initiator.command.executed"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local threats = {{
    pattern = [=[(?:^|\s+|"|'|\\)net1?\s+accounts[\\\s"'\:;)]]=],
    name = "Получение информации о парольной локальной политике через net accounts",
    risk = 6.0,
    mitre = {"T1021"}
}, {
    pattern = [=[(?:^|\s+|"|'|\\)(?:get\\-passpol|get\\-domainpolicy)[\\\s"'\:;)]]=],
    name = "Использование утилит PowerView/PowerSploit для получения парольной политики",
    risk = 8.5,
    mitre = {"T1021"}
}, {
    pattern = [=[(?:^|\s+|"|'|\\)get\-addefaultdomainpasswordpolicy[\\\s"'\:;)]]=],
    name = "Получение парольной политики домена через Active Directory PowerShell",
    risk = 6.5,
    mitre = {"T1021"}
}, {
    pattern = [=[(?:^|\s+|"|'|\\)secedit(\.exe)?\s+\/export([\s\S]*)?securitypolicy[\\\s"'\:;)]]=],
    name = "Экспорт локальной политики безопасности через secedit",
    risk = 7.0,
    mitre = {"T1021"}
}, {
    pattern = [=[(?:^|\s+|"|'|\\)wmic\s+useraccount\s+get([\s\S]*)?password[\\\s"'\:;)]]=],
    name = "Запрос параметров паролей пользователей через WMIC",
    risk = 6.5,
    mitre = {"T1021", "T1087.001"}
}}

-- Вспомогательная функция логирования значений в группере (удалить после тестирования на потоке)
local function log_grouper(events, events_number, unique_events, grouper_name, grouper_field)
    log("### " .. grouper_name .. " ###")
    log("Events: " ..#events.. ". Unique events: " ..unique_events)
    
    for _, event in ipairs(events) do
	    log("Event ID: " .. tostring(event:gets("observer.event.id")))
        log("Grouper field: " .. tostring(event:gets(grouper_field))) 
    end    
end

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
    local command_executed = logline:gets("initiator.command.executed")
    local is_password, title, risk, mitre = command_executed:search(threats) 

    if is_password then
        set_field_value(logline, "event.rule.description", title)
        set_field_value(logline, "event.application.risk", risk)
        set_field_value(logline, "mitre.technique", mitre)
        grouper1:feed(logline)
    end
end

-- Функция группера для одного события 4688
function on_grouped(grouped)
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