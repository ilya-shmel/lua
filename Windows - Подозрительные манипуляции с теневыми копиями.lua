-- Шаблон алерта
local template = [[
{{ .Meta.title }}.

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{ or .Meta.ip "IP-адрес не определён" }}
Хост: {{ or .Meta.hostname "Имя узла не определено" }}
FQDN: {{ or .Meta.observer_fqdn "FQDN узла не определено" }}

ИНИЦИАТОР:
Пользователь: {{ or .Meta.user "Пользователь не определён"}}

ВЫПОЛНЕННАЯ КОМАНДА:
{{ .Meta.command }}
Путь к исполняемому файлу: {{ .Meta.path }}
Имя службы: {{ .Meta.service }}
Статус задачи: {{ .Meta.status }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local patterns = {
    VSSADMIN = {
        short_pattern = "vssadmin",
        main_pattern = [["?[^"]*vssadmin(?:\.exe)?"?\s+(?:create\s+shadow|(?:delete|list)\s+shadows)(?:\/|\s+|"|')[\s\S]*]],
        name = "Обнаружено создание, удаление или перечисление теневых копий Volume Shadow Copy"
    },
    DISKSHADOW = {
        short_pattern = "diskshadow",
        main_pattern = [["?[^"]*diskshadow(?:\.exe)?"?\s*(?:\/s\s+\S+|[\s\S]*(?:\/|\s+|"|')(create|expose|delete|list)(?:\/|\s+|"|')[\s\S]*)]],
        name = "Обнаружено использование DiskShadow для управления теневыми копиями Volume Shadow Copy"
    },
    WMIC = {
        short_pattern = "wmic",
        main_pattern = [["?[^"]*wmic(?:\.exe)?"?(\s+\/node:[^:]+)?\s+shadowcopy\s+(?:call\s+create|delete|list)(?:\/|\s+|"|')[\s\S]*]],
        name = "Обнаружено использование WMIC для создания, удаления или перечисления теневых копий Volume Shadow Copy"
    },
    GMI = {
        short_pattern = "gwmi",
        main_pattern = [[(?:\/|\s+|"|'|\()gwmi\s+-list[^)]+\)\.create\(['"]?\w:\\['"],['"]?\w+['"]\)(?:\/|\s+|"|'|\))]],
        name = "Обнаружено использование PowerShell (GWMI) для создания, удаления или перечисления теневых копий Volume Shadow Copy"
    }
}

-- Функция сокращения строки для алерта
local function string_cut(cmd)
    if #cmd > 128 then
        cmd = cmd:sub(1, 128).. "... "
    end

    return cmd
end

-- Функция анализа строки по регулярному выражению
local function analyze(cmd)
    local cmd = cmd:lower()

    for _, pattern in pairs(patterns) do
        if substr(cmd, pattern.short_pattern) then
            if cmd:search(pattern.main_pattern) then
                local title = pattern.name
                return title, true
            end
        end
    end
    
    return false
end

-- Функция обработки логлайна
function on_logline(logline)
    local title

    if compare(logline:gets("observer.event.id"), "==", "4688") then
        title, is_vss = analyze(logline:gets("initiator.command.executed"))

        if is_vss then
            set_field_value(logline, "event.rule.description", title)
            grouper1:feed(logline)
        end
    else
        grouper1:feed(logline)
    end
end

-- Функция группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec, log_service
    
    if unique_events > 1 then
        for _, event in ipairs(events) do
            if compare(event:gets("observer.event.id"), "==", "4688") then
                log_exec = event
            else
                log_service = event
            end
        end

        if log_exec and log_service then
            local initiator_name = log_exec:gets("initiator.user.name")  
            local host_ip = log_exec:gets("observer.host.ip")
            local host_name = log_exec:gets("observer.host.hostname")
            local host_fqdn = log_exec:gets("observer.host.fqdn")
            local service_name = log_service:gets("target.service.name")
            local command_executed = string_cut(log_exec:gets("initiator.command.executed"))
            local process_path = log_exec:gets("initiator.process.parent.path.original")
            local task_status = log_service:gets("target.task.status.name")
            local description = log_exec:gets("event.rule.description")

            alert({
               template = template,
               meta = {
                   title=description,
                   user=initiator_name,
                   command=command_executed,
                   path=process_path,
                   service=service_name,
                   status=task_status,
                   ip=host_ip,
                   hostname=host_name
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
               mitre = {"T1003.003", "T1490"},
               trim_logs = 10
               }
            )
            grouper1:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)