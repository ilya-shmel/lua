-- Шаблон алерта
local template = [[
	Обнаружено получение содержимого файла формата sh из GitHub и его исполнение посредством bash.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор загрузки): {{ .Meta.user_name1 }}
    Команда получения скрипта: {{ .Meta.first_command }}
    Путь исполнения: {{ .Meta.command_path1 }}
    Пользователь(инициатор выполнения): {{ .Meta.user_name2 }}
    Команда выполнения скрипта: {{ .Meta.second_command }}
    Путь исполнения: {{ .Meta.command_path2 }} 
]]

-- Переменные для групперов
local detection_window = "3m"
local grouped_time_field = "@timestamp,RFC3339"
local grouped_by1 = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local grouped_by2 = {"target.file.name"}
local aggregated_by1 = {"observer.event.type"}
local aggregated_by2 ={"operation.type"}

-- Массив с регулярными выражениями
local prefix = "(?:^|\\/|\\s+|\"|\')" 
local bins = "\\b(?:wget|git|http|hub|glab|gh|curl|lwp-download|aria2c|axel|svn|python|\\.sh)\\b"
local git_patterns = {
        "(?:\'|\")?http(s)?:\\/{2}(raw\\.)?github(usercontent)?\\.com\\/([^\\/\\s]+\\/?)+\\.sh(?:\'|\")?",
        "(?:\'|\")?git@github\\.com:[\\w\\/\\.]+\\s+\\w+\\s+\\/?[^\\/\\s]+(\\.sh)?(?:\'|\")?",
        prefix .. "(?:hub|glab|git|gh)\\s+(repo\\s+)?clone\\s+(?:\"|\')?[\\w\\/]+(?:\"|\')?",
        prefix .. "gh\\s+api\\s+(?:\"|\')?[\\w\\/]+(\\/\\w+\\.sh)(?:\"|\')?"
}

local shell_pattern = prefix .. "\\b(?:zsh|ksh|bash|dash|chsh|sh)\\b(\\s+(\\.?(\\/[^\\/ ]*)+)?\\w+\\.sh)?"

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
    local is_shell = cmd_pipe:search(shell_pattern)
    if is_shell then
        return is_shell
    end
end

-- Проверка path name
local function analyze_syscall(path)
    local sys_path = path:lower()
    local is_bin = sys_path:search(bins)
    local is_shell = sys_path:search(shell_pattern)
    if is_bin or is_shell then
       return true
    end
end

-- Функция поиска строк, похожих на файл
local function like_filename(full_filename)
-- Захватываем последний сегмент пути (basename) без '/', '?' и '"' —
-- допускается опциональная начальная кавычка и любая директория перед ней.
  local _, basename = full_filename:match('^"?(.*/)?([^/%?"]+)')
  if basename then 
  -- Условия: не пустое, не начинается с '-', содержит хотя бы одну букву/цифру
    if basename == "" or basename:sub(1,1) ~= "" or basename:match("^[^%a%d]*$") then
        return nil
    else 
        return basename
    end
  end
end

-- Функция поиска точного имени файла
local function extract_filename(filename)
-- Ищем аргумент -O/-o, допускаем опциональную начальную кавычку,
-- захватываем (необязательную) директорию и затем filename без '/', пробелов, '?' и '"'.
  local _, extracted_filename = filename:match('%-[Oo]%s*"?(.*/)?([^/%s%?"]+)')
-- Позитивная проверка: возвращаем basename только если он валиден по вашим правилам
  if extracted_filename and extracted_filename ~= "" and extracted_filename:sub(1,1) ~= "-" and extracted_filename:match("%w") then
      return extracted_filename
  end

  for substring in filename:gmatch("%S+") do
    local base_filename = like_filename(substring)
    if base_filename then 
      return base_filename
    end
  end
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
--    local object_type = logline:gets("target.object.type")
    local command_executed = logline:gets("initiator.command.executed")
    local path_name = logline:gets("initiator.process.path.name")
    local syscall_name = logline:gets("target.syscall.name")

    if event_type == "EXECVE" or event_type == "PROCTITLE" then
        local is_git = analyze_git(command_executed)
        local shell_command = is_shell_exec(command_executed)
--
        if is_git or shell_command then
            grouper1:feed(logline)
	    end     
-- Проверяем SYSCALL - нужен только execve и c интересующим нас именем исполняемого файла    
    elseif event_type == "SYSCALL" and syscall_name == "execve" then
        local syscall_filter = analyze_syscall(path_name)
        if syscall_filter then
            grouper1:feed(logline)        
        end
    end
end

-- Функция сработки группера #1
function on_grouped1(grouped)
    local events = grouped.aggregatedData.loglines
    local target_file = ""
    local operation_type = ""
    local user_name = ""
    
    if grouped.aggregatedData.unique.total > 1 then
        for _, event in ipairs(events) do
            if event:gets("observer.event.type") == "SYSCALL" then
                log_sys = event
            else
                log_exec = event
            end
        end

        if log_sys ~= "" and log_exec ~= "" then
            local current_command = log_exec:gets("initiator.command.executed"):lower()
            target_file = extract_filename(current_command)
            
            for _, pattern in ipairs(git_patterns) do
                local search_operation = analyze_git(log_exec:gets("initiator.command.executed"))
                if search_operation then
                    operation_type = "download"
                else 
                    operation_type = "execution"
                end
            end
            
            local user_name = log_sys:gets("initiator.user.name")
            local path_name = log_sys:gets("initiator.process.path.full")
            set_field_value(log_exec,"initiator.user.name", user_name)
            set_field_value(log_exec,"operation.type", operation_type)
            set_field_value(log_exec,"target.file.name", target_file)
            set_field_value(log_exec,"path.name", path_name)   
            set_field_value(log_sys, "operation.type", operation_type)
            set_field_value(log_sys, "target.file.name", target_file)       
            
            grouper2:feed(log_exec)
            grouper2:feed(log_sys)
            grouper1:clear()
        end
    end 
end

-- Функция сработки группера #2
function on_grouped2(grouped)
    local events = grouped.aggregatedData.loglines
    local commands = {}
    local users = {}
    local process_path = {}
    

    if grouped.aggregatedData.unique.total > 1 then
        for _, event in ipairs(events) do
            if (event:gets("observer.event.type") == "EXECVE" or event:gets("observer.event.type") == "PROCTITLE") and event:gets("operation.type") == "download" then
                commands[1] = event:gets("initiator.command.executed")
                users[1] = event:gets("initiator.user.name")
                process_path[1] = event:gets("path.name")
            elseif (event:gets("observer.event.type") == "EXECVE" or event:gets("observer.event.type") == "PROCTITLE") and event:gets("operation.type") == "execution" then
                commands[2] = event:gets("initiator.command.executed")
                users[2] = event:gets("initiator.user.name")
                process_path[2] = event:gets("path.name")
            end

            if commands[1] and #commands[1] > 128 then
                commands[1] = commands[1]:sub(1,128).. "..."
            end
        end

        if commands[1] and commands[2] then
            local host_name = events[1]:gets("observer.host.hostname")
            local host_ip = events[1]:gets("observer.host.ip")
            local host_fqdn = events[1]:gets("observer.host.fqdn")        
    
-- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name1 = users[1],
                    user_name2 = users[2],
                    first_command = commands[1],
                    second_command = commands[2],
                    command_path1 = process_path[1],
                    command_path2 = process_path[2]
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
            grouper2:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by1, aggregated_by1, grouped_time_field, detection_window, on_grouped1)
grouper2 = grouper.new(grouped_by2, aggregated_by2, grouped_time_field, detection_window, on_grouped2)