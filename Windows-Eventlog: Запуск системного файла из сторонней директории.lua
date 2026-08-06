-- Табличные списки
blacklist = storage.new("Names of system files")
whitelist = storage.new("wl_utilName|Windows: Запуск системного файла из сторонней директории")

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
Родительский процесс: {{ .Meta.parent }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "target.image.name"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

local system_paths = {
                    [[c:\windows\]],
                    [[c:\program files (x86)\]],
                    [[c:\program files\]],
                    [[c:\users\default\appdata\]],
                    [[c:\programdata\]],
                    [[c:\perflogs\]],
                    [[c:\recovery\]]
}
local suspicious_paths = {
                    [[c:\\programdata\\]],
                    [[c:\\users\[\s\S]*\\appdata\\local\\temp\\]],
                    [[c:\\windows\\temp\\]]
}

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
        mitre = meta.risk,
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
    local image_name = logline:gets("target.image.name"):lower()
    local path_full = logline:gets("target.process.path.full"):lower()
    local is_system_file = blacklist:search("наименование", image_name)
    local is_legal = whitelist:search("file_name", image_name)

    if image_name == "cmd.exe" or image_name == "powershell.exe" then -- Добавлена проверка на запуск интерпретаторов из системных, но нехарактерных директорий
        for _, pattern in ipairs(suspicious_paths) do
            if path_full:search(pattern) then grouper1:feed(logline) end
        end
    elseif is_system_file then
        if is_legal or contains(system_paths, path_full, "prefix") then return end
        grouper1:feed(logline)
    end
end

-- Функция группера
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
            fqdn=first_event:gets("observer.host.fqdn"),
            risk=4.0,
            mitre={"T1036"},
            title="Обнаружен запуск системного файла из сторонней директории"
        }

        alert_function(events, meta)
        grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)