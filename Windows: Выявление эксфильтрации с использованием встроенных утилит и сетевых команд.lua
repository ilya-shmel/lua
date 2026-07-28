-- Шаблон алерта
local template = [[
{{ .Meta.title }}

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
Родительский процесс {{ .Meta.parent }} 
]]

-- Переменные для группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "target.image.name"}
local aggregated_by = {"initiator.command.executed"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local arch_patterns = {
    RAR = {
            short_pattern = "rar%.exe",
            main_pattern = [[(?:^|\s+|"|'|\/|\\|{)(win)?rar\.exe[\\\s"'\:;)]([\s\S]*)?\.rar(?:$|['"]?\s+([\s\S]*)?[*.]\w+)]],
            name = "Подозрение на эксфильтрацию с использованием утилиты WinRar."
    },
    SEVENZ = {
            short_pattern = "7z%.exe",
            main_pattern = [[(?:^|\s+|"|'|\\|{)7z\.exe[\\\s"':;)]\s+\w([\s\S]*)\.7z\s+\*\w{1,6}]],
            name = "Подозрение на эксфильтрацию с использованием утилиты 7z."
    },
    ZIP = {
            short_pattern = "(zip(64)?%.exe)",
            main_pattern = [[(?:^|\s+|"|'|\\|{)(win)?zip(64)?\.exe[\\\s"'\:;)](\s+-[\w"']+)+\s+\w+\.zip[\s*]+]],
            name = "Подозрение на эксфильтрацию с использованием утилиты zip."
    },
    PLINK = {
            short_pattern = "(plink%.exe)",
            main_pattern = [[(?:^|\s+|"|'|\/|\\|{)plink\.exe[\\\s"'\:;)](\s+-(?:ssh|l|pw|password|m)\s+[\w.\/:~\\]+)+]],
            name = "Подозрение на эксфильтрацию с использованием утилиты plink."
    },
    MAKECAB = {
            short_pattern = "(makecab%.exe)",
            main_pattern = [[(?:^|\s+|"|'|\/|\\|{)makecab(\.exe)?[\\\s"'\:;)](\s+)?(\w:(\\[^\\\s]*)+)?\w+\.\w{1,8}\s+(\w:(\\[^\\\s]*)+)?\.(?:zip|rar|7z|cab|dat)]],
            name = "Подозрение на эксфильтрацию с использованием утилиты makecab."
    }
}

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
        mitre = {"T1020", "T1560.001"},
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
-- Функция анализа строки
local function analyze(cmd)
    local cmd_string = cmd:lower()
    
    for _, pattern in pairs(arch_patterns) do
        if cmd_string:match(pattern.short_pattern) then
            if cmd_string:search(pattern.main_pattern) then
                return true, pattern.name
            end         
        end
    end

    return false
end

-- Функция работы с логлайном
function on_logline(logline)
    local command_executed = logline:gets("initiator.command.executed")
    local is_command, title = analyze(command_executed)
    set_field_value(logline,"event.rule.description", title)

    if is_command then
       grouper1:feed(logline)
    end
end

-- Функция сработки группера
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
            ip=first_event:gets("observer.host.ip"),
            hostname=first_event:gets("observer.host.hostname"),
            fqdn=first_event:gets("observer.host.fqdn")
        }

        alert_function(events, meta)
        grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)