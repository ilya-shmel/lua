-- Шаблоны алерта
local template = [[
	Подозрение на динамический обмен данными.

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{ or .Meta.ip "IP-адрес не определён" }}
Хост: {{ or .Meta.hostname "Имя узла не определено" }}
FQDN: {{ or .Meta.observer_fqdn "FQDN узла не определено" }}

ИНИЦИАТОР:
Пользователь: {{.Meta.user_name}}
Процесс: {{.Meta.path}}
Идентификатор родительского процесса: {{.Meta.parent_pid}}
Идентификатор "дочернего" процесса: {{.Meta.child_pid}}

ВЫПОЛНЕННАЯ КОМАНДА:
{{.Meta.command}}
]]

-- Переменные для группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "event.process.id"}
local aggregated_by = {"target.image.name"} -- observer.event.id
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local prefix = "(?:^|\\/|\\s+|\"|\'|\\\\)" 
local command_patterns = {
        ["cmd_execution"] = prefix.. "(-\\w+(\\s+[^-\\s]+)?\\s*)+\\s+(?:\"|\')[\\s\\S]*(?:\"|\')",
        ["office_root"] = prefix.. "\\s+\\/n\\s+(?:\'|\")(([^\\\\]+\\\\)+)?\\w+\\.(?:do|xl|p[po])(?:[sta]|[ct])[mx]?(?:\'|\")\\s+\\/o"
}

local shell_commands = { "powershell.exe", "cmd.exe", "pwsh.exe" }

-- Функция анализа строки
local function analyze(cmd, pattern)
    if cmd:search(pattern) then return true end
    
    return false
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")
    local command_executed = logline:gets("initiator.command.executed"):lower()

    if compare(event_id, "==", "4688") then
        local target_image = logline:gets("target.image.name"):lower()

        if contains(shell_commands, target_image, "sub") then
            if analyze(command_executed,command_patterns["cmd_execution"]) then
                local parent_id = logline:gets("initiator.process.parent.id")
                set_field_value(logline, "event.process.id", parent_id)
                grouper1:feed(logline)
            end
        else
            if analyze(command_executed,command_patterns["office_root"]) then
                local target_id = logline:gets("target.process.id")
                set_field_value(logline, "event.process.id", target_id)
                grouper1:feed(logline)
            end
        end
    else
        log("Do nothing")
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_cmd_exec, log_office_root

    if unique_events > 1 then
       log("All works normally")
       grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)