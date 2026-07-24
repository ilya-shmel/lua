-- Шаблон алерта
local template = [[
Подозрение на запуск утилиты AppCmd.exe из пакета Web-Server с целью хищения реквизитов доступа.

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
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "target.image.name"}
local aggregated_by = {"initiator.command.executed"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local webserver_pattern = [[(?:^|[\\;\s"'(])appcmd(\.exe)?[\\\s"'\)]?(\s+)?list\s+apppool\s+\/(?:[@:*\w]+|config)]]

-- Функция алерта
local function alert_function(events, meta)
    alert({
        template = template,
        meta = meta,
        risk_level = 7.5, 
        asset_ip = meta.ip,
        asset_hostname = meta.hostname,
        asset_fqdn = meta.fqdn,
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

    if command_executed:search(webserver_pattern) then
        grouper1:feed(logline)
    end
end

-- Функция группера #1
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
            ip=first_event:gets("observer.host.ip"),
            hostname=first_event:gets("observer.host.hostname"),
            fqdn=first_event:gets("observer.host.fqdn")
        }

        alert_function(events, meta)
        grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)