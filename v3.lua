-- Шаблон алерта
local template = [[
	Обнаружено получение содержимого файла формата sh из GitHub и его исполнение посредством bash.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Команда получения скрипта: {{ .Meta.first_command }}
    Команда выполнения скрипта: {{ .Meta.second_command }}
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]

-- Переменные для групера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Массив с регулярными выражениями
local prefix = "(?:^|\\/|\\s+|\"|\')" 

local git_patterns = {
        "(?:\'|\")?http(s)?:\\/{2}(raw\\.)?github(usercontent)?\\.com\\/([^\\/\\s]+\\/?)+\\.sh(?:\'|\")?",
        "(?:\'|\")?git@github\\.com:[\\w\\/\\.]+\\s+\\w+\\s+\\/?[^\\/\\s]+(\\.sh)?(?:\'|\")?",
        prefix .. "(?:hub|glab|git|gh)\\s+(repo\\s+)?clone\\s+(?:\"|\')?[\\w\\/]+(?:\"|\')?",
        prefix .. "gh\\s+api\\s+(?:\"|\')?[\\w\\/]+(\\/\\w+\\.sh)(?:\"|\')?"
}

local shell_pattern = prefix .. "((\\/usr)?\\/bin\\/)?([a-z]{1,2})?sh\\b"

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze_git(cmd)
    local cmd_string = cmd:lower()
    
    for _, pattern in pairs(git_patterns) do
            local regular1 = cmd_string:search(pattern)
            if regular1 then
                return regular1
            end
    end
end

-- Проверка второй команды (/bin/sh)
local function is_shell_exec(shell)
    local cmd_pipe = shell:lower()
    local regular2 = cmd_pipe:search(shell_pattern)
    if regular2 then
        return regular2
    end
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    local object_type = logline:gets("target.object.type")
    local command_executed = logline:gets("initiator.command.executed")
    local path_name = logline:gets("initiator.process.path.name")
    local syscall_name = logline:gets("target.syscall.name")

    if event_type == "EXECVE" or event_type == "PROCTITLE" then
	    local is_git = analyze_git(command_executed)
        local shell_command = is_shell_exec(command_executed)
           if is_git or is_shell_exec then
              grouper1:feed(logline)
	    end
    end

    if event_type == "SYSCALL" and syscall_name == "execve" then
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local event_count = #events
    local git_marker = false
    local shell_marker = false
    local git_timestamp = nil
    local shell_timestamp = nil
    log(event_count)
    local log_sys = {}
    local log_exec = {}
    local commands = {}

-- "Разбиваем" события на SYSCALL и EXECVE/PROCTITLE
    for _, event in ipairs(events) do
        if event:gets("observer.event.type") == "SYSCALL" then
            table.insert(log_sys, event)
        else
            table.insert(log_exec, event)
        end
    end
    
-- Ищем последовательность команд и проверяем одновременное наличие EXECVE/PROCTITLE и SYSCALL    
    if #log_exec >= 2  and #log_sys >= 1 then
        for _, exec_event in ipairs(log_exec) do
            current_command = exec_event:gets("initiator.command.executed")
            if analyze_git(current_command) then
                git_marker = true
                git_timestamp = exec_event:gets("timestamp")
                commands[1] = current_command
            elseif is_shell_exec(current_command) and git_marker then
                shell_marker = true
                shell_timestamp = exec_event:gets("timestamp")
                commands[2] = current_command
                break -- Последовательность обнаружена
            end        
        end
    end

-- Алертим только если обнаружена правильная последовательность
    if git_marker and shell_marker then
-- Режем слишком длинные команды
        if #commands[1] > 128 then
            commands[1] = commands[1]:sub(1,128).. "..."
        end

        local user_name = log_sys[1]:gets("initiator.user.name")
        local host_name = log_exec[1]:gets("observer.host.hostname")
        local host_ip = log_exec[1]:gets("observer.host.ip")
        local host_fqdn = log_exec[1]:gets("observer.host.ip")
        local process_path = log_sys[1]:gets("initiator.process.path.full")

-- Функция алерта
        alert({
            template = template,
            meta = {
                user_name = user_name,
                first_command = commands[1],
                second_command = commands[2],
                command_path = process_path
                },
            risk_level = 8.0, 
            asset_ip = host_ip,
            asset_hostname = host_name,
            asset_fqdn = host_fqdn,
            asset_mac = "",
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "",
            logs = grouped.aggregatedData.loglines,
            mitre = {"T1059.004"},
            trim_logs = 10
            }
        )
        grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)