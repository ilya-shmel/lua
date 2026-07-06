-- Шаблон алерта
local template = [[
Подозрение на маскировку процесса через SYSCALL vfork и SYSCALL clone.

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{ or .Meta.ip "IP-адрес не определён" }}
Хост: {{ or .Meta.hostname "Имя узла не определено" }}
FQDN: {{ or .Meta.observer_fqdn "FQDN узла не определено" }}

ИНИЦИАТОР:
Пользователь: {{ or .Meta.user "Пользователь не определён"}}

ВЫПОЛНЕННАЯ КОМАНДА:
{{ .Meta.command }}
Процесс/Путь к имполняемому файлу: {{ .Meta.path }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}
local aggregated_by = {"target.syscall.name"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local prefix = "(?:^|\\/|\\s+|\"|\'|\\()"
local suffix = "(?:$|\\/|\\s+|\"|\'|\\))"
local suspicious_patterns = {   
                        
}

-- Функция сокразения строки для алерта
local function string_cut(cmd)
    if #cmd > 128 then
        cmd = cmd:sub(1, 128).. "... "
    end

    return cmd
end

-- Функция анализа строки по регулярному выражению
local function analyze(cmd)
    local cmd_lower = cmd:lower()
    for _, pattern in ipairs(suspicious_patterns) do
        if cmd_lower:search(pattern) then
            return true
        end
    end
    return false
end

-- Функция обработки логлайна
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    local event_id = logline:gets("observer.event.id")
    ...
    grouper1:feed(logline)
end

-- Функция группера #1
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_1, log_2
    
    if unique_events > 1 then
        for _, event in ipairs(events) do
            local parameter = event:gets("..."):lower()

            if syscall_name == "" then
                log_1 = event
            else
                log_2 = event
            end
        end

        if log_1 and log_2 then
            local initiator_name = log_1:gets("initiator.user.name")  
            local host_ip = log_2:get("observer.host.ip")
            local host_name = log_2:gets("observer.host.hostname")
            local host_fqdn = log_2:gets("observer.host.fqdn")
            local program_name = log_1:gets("target.image.name")
            local command_executed = log_2:gets("initiator.command.executed")
            local process_path = log_2:get("target.process.path.full")

            if #command_executed > 255 then
                command_executed = command_executed:sub(1,255) .. "... "
            end
                        
            alert({
               template = template,
               meta = {
                   user=initiator_name,
                   initiator_command=command_executed,
                   path=process_path,
                   program=program_name,
                   ip=host_ip,
                   hostname=host_name
                   },
               risk_level = 4.0, 
               asset_ip = host_ip,
               asset_hostname = host_name,
               asset_fqdn = host_fqdn,
               asset_mac = "",
               create_incident = true,
               incident_group = "",
               assign_to_customer = false,
               incident_identifier = "",
               logs = events,
               mitre = {"T1036.004"},
               trim_logs = 10
               }
            )
            grouper1:clear()
        end

    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)

