-- Шаблоны алерта
local template = [[
	{{ .Meta.title }}.

    Узел: 
    IP-адрес: {{ or .Meta.ip "IP-адрес не определён" }}
    Имя узла: {{ .Meta.hostname }}
    Пользователь (инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Исполняемый файл/командлет: {{ .Meta.path }}
]]

local alert_titles = {
    { image = "python", title = "Использование Python для последовательного сканирования портов" },
    { image = "nmap", title = "Использование Nmap для последовательного сканирования портов" },
    { image = "portqry", title = "Атака через PortQry" },
    { image = "test-netconnection", title = "PowerShell: Инициализация последовательных сетевых подключений (Port Knocking)" },
    { image = "telnet", title = "Использование сетевых утилит для обхода закрытых портов (Port Knocking)" },
    { image = "nc", title = "Использование сетевых утилит для обхода закрытых портов (Port Knocking)" },
    { image = "ncat", title = "Использование сетевых утилит для обхода закрытых портов (Port Knocking)" },
    { image = "netcat", title = "Использование сетевых утилит для обхода закрытых портов (Port Knocking)" },
    { image = "masscan", title = "Использование утилиты Massscan для последовательного сканирования портов" },
    { image = "portqry", title = "Использование утилиты PortQry для последовательного сканирования портов" }
}

-- Переменные для группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "event.process.id", "initiator.command.info"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

function extract_image_name(command_string)
    command_string = command_string:lower()
    local path, filename, image_name, interpreter_name
    interpreter_name = command_string:match("[^%s;\\]?python%s+") -- Проверка на запуск файла через Python
    
    if interpreter_name then
        return interpreter_name:gsub("%s", "")
    else    
        path = command_string:match('"([^"]+)"') or command_string:match('^(%S+)') -- Ищем путь в кавычках. Если нет кавычек, то берём первое слово
    
        if path then
            filename = path:match('([^\\/]+)$')  -- Извлекаем имя файла из пути
            image_name = filename:match('(.+)%.exe$') or filename -- Убираем расширение .exe

            return image_name
        end
    end
    
    return "Имя файла не определено"
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")
    local command_executed = logline:gets("initiator.command.executed"):lower()
    
    if compare(event_id, "==", "4104") then
        local ip_address = command_executed:match("%d+%.%d+%.%d+%.%d+") -- Проверяем наличие IP-адреса в команде, если есть - отправляем в группер

        if ip_address then
            local command_info = extract_image_name(command_executed)
            local process_id = logline:gets("observer.process.id")
            set_field_value(logline, "event.process.id", process_id)
            set_field_value(logline, "initiator.command.info", command_info)
            grouper1:feed(logline)
        end
    elseif compare(event_id, "==", "4688") then
        local target_image = logline:gets("target.image.name"):lower()
        local command_info = target_image:match("[^%.]+")
        local process_id = logline:gets("initiator.process.parent.id")
        process_id = tonumber(process_id:gsub("^0[xX]", ""), 16)
        set_field_value(logline, "event.process.id", process_id)
        set_field_value(logline, "initiator.command.info", command_info)
        grouper1:feed(logline)
    elseif compare(event_id, "==", "4103") then
        local process_command = logline:gets("initiator.process.command"):lower()
        local process_id = logline:gets("observer.process.id")
        set_field_value(logline, "event.process.id", process_id)
        set_field_value(logline, "initiator.command.info", process_command)
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_scriptblock = nil
    local log_exec = nil
    local current_title = "Обнаружена проверка портов с помощью штатных или специальных утилит"
--    local log_module = nil
    
    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")

            if compare(event_id, "==", "4104") then
                log_scriptblock = event
            else
                log_exec = event
            end
        end

        if log_scriptblock and log_exec then
            local initiator_name = log_exec:gets("initiator.user.name", "Пользователь не определен")  
            local host_ip = log_scriptblock:get("observer.host.ip") or log_scriptblock:get("reportchain.collector.host.ip")
            local host_name = log_scriptblock:gets("observer.host.hostname", "Имя узла не опредено")
            local host_fqdn = log_scriptblock:gets("observer.host.fqdn")
            local command_executed = log_scriptblock:gets("initiator.command.executed")
            local target_image = log_exec:get("target.image.name") or log_exec:get("target.process.path.full") or log_exec:get("initiator.process.command") or "Имя файла не определено"
            local command_name = log_scriptblock:get("initiator.command.info") or log_exec:get("initiator.command.info") 

            for _, pattern in pairs(alert_titles) do
                if command_name == pattern.image then
                    current_title = pattern.title
                end
            end

            if #command_executed > 128 then
                 command_executed = command_executed:sub(1,128).. "..."
            end

            alert({
                 template = template,
                 meta = {
                     user_name=initiator_name,
                     command=command_executed,
                     path=target_image,
                     ip=host_ip,
                     hostname=host_name,
                     title=current_title
                     },
                 risk_level = 7.0, 
                 asset_ip = host_ip,
                 asset_hostname = host_name,
                 asset_fqdn = host_fqdn,
                 asset_mac = "",
                 create_incident = true,
                 incident_group = "",
                 assign_to_customer = false,
                 incident_identifier = "",
                 logs = events,
                 mitre = {"T1046", "T1205.001", "T1558.003", "T1558.004", "T1187", "T1082", "T1518"},
                 trim_logs = 10
                 }
            )
            grouper1:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)