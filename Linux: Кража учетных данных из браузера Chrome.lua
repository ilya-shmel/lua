local template = [[
ОБНАРУЖЕНА ПОПЫТКА КРАЖИ УЧЕТНЫХ ДАННЫХ ИЗ CHROME

СИСТЕМНАЯ ИНФОРМАЦИЯ
Узел: {{ if .First.observer.host.hostname }}{{ .First.observer.host.hostname }}{{ else }}{{ .First.observer.host.ip }}{{ end }}
IP: {{ if .First.observer.host.ip }}{{ .First.observer.host.ip }}{{ else }}unknown{{ end }}
{{ if .First.observer.host.fqdn }}FQDN: {{ .First.observer.host.fqdn }}{{ end }}

ПОЛЬЗОВАТЕЛЬ
{{ .Meta.user_name }}
Процесс: {{ .Meta.process_path }}

ВЫПОЛНЕННАЯ КОМАНДА
{{ .Meta.command }}

АНАЛИЗ УГРОЗЫ
Тип операции      : {{ .Meta.operation_type }}
Целевой ресурс    : {{ .Meta.target_resource }}
Метод извлечения  : {{ .Meta.extraction_method }}
Уровень риска     : {{ .Meta.risk_level }}

ОПИСАНИЕ УГРОЗЫ
{{ .Meta.threat_description }}

Время обнаружения: {{ .Meta.timestamp }}
Event ID: {{ .First.observer.event.id }}
]]


local detection_window = "1m"
local create_incident = true
local assign_to_customer = false
local grouped_time_field = "@timestamp,RFC3339"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}


-- Команды извлечения данных
local extraction_commands = {
    ["SQL-запрос к базе данных браузера"] = "sqlite3",
    ["Копирование/перемещение файлов браузера"] = "cat",
    ["Чтение файлов браузера"] = "cp",
    ["Доступ к данным браузера"]= "mv",
    ["Доступ к данным браузера"]= "dd",
    ["Архивирование данных браузера"]= "tar",
    ["Архивирование данных браузера"]= "zip",
    ["Архивирование данных браузера"]= "7z",
    ["Доступ к данным браузера"]= "strings",
    ["Извлечение строк из бинарных файлов"]= "grep"
}


-- Функция определения типа операции
local function detect_operation_type(command)
    local cmd_lower = string.lower(command)
    
    local comm_name = string.match(cmd_lower, "[^%s+/]%S+")
    if comm_name == "sqlite3" then
        return "SQL-запрос к базе данных браузера"
    elseif comm_name == "cp" or comm_name == "mv" then
        return "Копирование/перемещение файлов браузера"
    elseif comm_name == "cat" then
        return "Чтение файлов браузера"
    elseif comm_name == "tar" or comm_name == "zip" or comm_name == "7z" then
        return "Архивирование данных браузера"
    elseif comm_name == "strings" then
        return "Извлечение строк из бинарных файлов"
    elseif comm_name == "grep" then
        return "Поиск в файлах браузера"
    else
        return "Доступ к данным браузера"
    end
end

-- Функция определения целевого ресурса
local function detect_target_resource(command)
    local cmd_lower = string.lower(command)
    local targets = {}
    
    if cmd_lower:search("(?:logins|Login Data (пароли))") then
        table.insert(targets, "Login Data (пароли)")
    end
    
    if cmd_lower:search("(?:cookies|cookie|Cookies (сессии))") then 
        table.insert(targets, "Cookies (сессии)")
    end
    
    if cmd_lower:search("(?:web data|Web Data (автозаполнение))") then  
        table.insert(targets, "Web Data (автозаполнение)")
    end
    
    if cmd_lower:search("(?:history|History (история))") then  
        table.insert(targets, "History (история)")
    end
    
    if #targets > 0 then
        return table.concat(targets, ", ")
    else
        return "Файлы Chrome (общие)"
    end
end

-- Функция определения метода извлечения
local function detect_extraction_method(command)
    local cmd_lower = string.lower(command)
    
    -- Проверяем SQL операции
    if cmd_lower:search("(?:select|(\\.)?dump|pragma|attach)") then
        return "SQL-запросы (прямое извлечение)"
    end
    
    -- Проверяем копирование
    if cmd_lower:search("(?:cp|mv)") then
        return "Копирование файлов БД"
    end
    
    -- Проверяем архивирование
    if cmd_lower:search("(?:tar|zip|7z)") then
        return "Архивирование для эксфильтрации"
    end
    
    return "Прямое чтение файлов"
end

-- Функция оценки уровня риска
local function assess_risk_level(command)
    local cmd_lower = string.lower(command)
    local score = 5.0
    local reasons = {}
    
    -- SQL операции (+3)
    if cmd_lower:search("(?:select|(\\.)?dump|pragma|attach)") then
        score = score + 3.0
        table.insert(reasons, "Использование SQL для извлечения")
    end
    
    -- Подозрительные термины (+2)
    if cmd_lower:search("(?:logins|password|encrypted_value|host_key|cookie|session)") then
        score = score + 2.0
        table.insert(reasons, "Целевой поиск учетных данных")
    end

    
    -- Копирование в /tmp (+1.5)
    if cmd_lower:search("\\/tmp\\/") then
        score = score + 1.5
        table.insert(reasons, "Копирование во временную директорию")
    end
    
    -- Архивирование (+1)
    if cmd_lower:search("(?:tar|zip|7z)") then
        score = score + 1.0
        table.insert(reasons, "Подготовка к эксфильтрации")
    end
    
    local level = "НИЗКИЙ"
    if score >= 9.0 then
        level = "КРИТИЧЕСКИЙ"
    elseif score >= 7.0 then
        level = "ВЫСОКИЙ"
    elseif score >= 5.5 then
        level = "СРЕДНИЙ"
    end
    
    return level, math.min(score, 10.0), reasons
end

-- Основная функция анализа
local function analyze(command)
    local cmd_lower = string.lower(command)
    local operation_type = nil
    
    -- Проверяем наличие команды извлечения
    local has_extraction_cmd = false
    for operation, cmd in pairs(extraction_commands) do
        if cmd_lower:search("(?:^|\\/|\\\\|\\s+|\'|\")" .. cmd .. "\\s+") then
            has_extraction_cmd = true
            operation_type = operation
            break
        end
    end
    
    if not has_extraction_cmd then
        return false
    end
    
    -- Проверяем наличие путей Chrome
    local has_chrome_path = false
    if cmd_lower:search("(?:\\.config/google-chrome|\\.config/chromium|\\.config/BraveSoftware|\\.config/microsoft-edge|\\.config/opera|google-chrome|chromium|brave)") then
        has_chrome_path = true
    end

    -- Проверяем наличие критических файлов
    local has_critical_file = false
    if cmd_lower:search("(?:Login Data|Cookies|Web\\s+Data|History|Bookmarks|Preferences|Local State)") then
        has_critical_file = true
    end
    
    -- Срабатываем если: (команда извлечения) И (путь Chrome ИЛИ критический файл)
    return has_extraction_cmd and (has_chrome_path or has_critical_file), operation_type
end

function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    local operation_type = nil
    
    if event_type == "EXECVE" or event_type == "PROCTITLE" then
        local command = logline:gets("initiator.command.executed")
        local result, operation_type  = analyze(command)
        if result then
            grouper1:feed(logline)
        end
        
    elseif event_type == "SYSCALL" then
        grouper1:feed(logline)
    end
end

function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_sys = nil
    local log_exec = nil
    local event_type_found = "Unknown"
    
    log(#events)
    log(events[1]:get("observer.event.type"))
    -- Разделяем события
    for _, event in ipairs(events) do
        local type = event:gets("observer.event.type")
        if type == "SYSCALL" then
            log_sys = event
        elseif type == "EXECVE" or type == "PROCTITLE" then
            log_exec = event
            event_type_found = type
        end
    end
    
    -- Проверяем наличие обоих типов
    if log_sys and log_exec then
        local command = log_exec:gets("initiator.command.executed")
        
        if command and analyze(command) then
            local operation_type = detect_operation_type(command)
            local target_resource = detect_target_resource(command)
            local extraction_method = detect_extraction_method(command)
            local risk_level_text, risk_score, reasons = assess_risk_level(command)
                        
            local threat_description = string.format(
                "Операция: %s\nЦелевой ресурс: %s\nМетод: %s\nПризнаки угрозы:\n  %s\nВозможная цель: Кража учетных данных для lateral movement/persistence\nMITRE ATT&CK: T1555.003 (Credentials from Web Browsers)",
                operation_type,
                target_resource,
                extraction_method,
                table.concat(reasons, "\n  ")
            )
            
            alert({
                template = template,
                meta = {
                    user_name = log_sys:gets("initiator.user.name", "Не определен"),
                    command = command,
                    process_path = log_sys:gets("initiator.process.path.full", "Не определен"),
                    operation_type = operation_type,
                    target_resource = target_resource,
                    extraction_method = extraction_method,
                    risk_level = risk_level_text,
                    event_type = event_type_found,
                    threat_description = threat_description,
                    timestamp = log_sys:gets("@timestamp")
                },
                risk_level = risk_score,
                asset_ip = log_exec:get_asset_data("observer.host.ip"),
                asset_hostname = log_exec:get_asset_data("observer.host.hostname"),
                asset_fqdn = log_exec:get_asset_data("observer.host.fqdn"),
                asset_mac = "",
                create_incident = create_incident,
                incident_group = "",
                assign_to_customer = assign_to_customer,
                incident_identifier = "",
                logs = grouped.aggregatedData.loglines,
                mitre = {"T1555", "T1555.003", "T1005"},
                trim_logs = 10
            })
            
            grouper1:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)
