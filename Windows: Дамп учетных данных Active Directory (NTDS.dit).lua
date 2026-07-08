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
Копируемый файл/объект: {{ .Meta.source_object }}
Целевой файл: {{ .Meta.target_file }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "event.process.id"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local patterns = {
    NTDSUTIL = {
        short_pattern = "ntdsutil",
        object_pattern = "%a:\\[^\" ]+",
        main_pattern = [[ntdsutil\s+?['"]?[^"']+ntds(?:'|")?\s+(['"]?[^'"]+['"]?\s+)?['"]?create[\s\S]*\w:(\\[^\\]+)+]],
        name = "Обнаружено создание дампа NTDS.dit через Install From Media"
    },
    ESENTUTL = {
        short_pattern = "esentutl",
        object_pattern = "%a:\\[^\" ]+",
        main_pattern = [[(?i)"?[^"]*esentutl(?:\.exe)?"?\s+.*(?:\/y|\/vss|\/d|\/m)\s+.*(?:ntds\.dit|\\windows\\ntds\\).*]],
        name = "Обнаружено использование Esentutl для копирования или работы с NTDS.dit через Volume Shadow Copy"
    },
    POWERSHELL = {
        short_pattern = "powershell",
        object_pattern = "%a:\\[^\" ]+",
        main_pattern = [[?[^"]*(?:powershell|pwsh)(?:\.exe)?"?\s+[\s\S]*(?:copy-item|invoke-ninjacopy|globalroot|harddiskvolumeshadowcopy)[\s\S]*ntds\.dit[\s\S]*]],
        name = "Обнаружено использование PowerShell для доступа к NTDS.dit, теневым копиям или credential dumping активности"
    },
    REG = {
        short_pattern = "reg%s+save",
        object_pattern = "%s+hk%w+\\%w+%s+",
        main_pattern = [[reg\s+save\s+['"]?hk\w{1,2}\\\w+['"]?\s+['"]?\w:\\[\s\S]*]],
        name = "Обнаружено сохранение веток реестра из теневой копии"
    },
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
        if cmd:find(pattern.short_pattern) then
            if cmd:search(pattern.main_pattern) then
                local title = pattern.name
                local target_object =cmd:match(pattern.object_pattern)
                return title, target_object, true
            end
        end
    end
    
    return false
end

-- Функция обработки логлайна
function on_logline(logline)
    local title, target_object

    if compare(logline:gets("observer.event.id"), "==", "4688") then
        title, target_object, is_ntdis = analyze(logline:gets("initiator.command.executed"))

        if is_ntdis then
            set_field_value(logline, "event.rule.description", title)
            set_field_value(logline, "target.object.name", target_object)
            set_field_value(logline,"event.process.id", logline:gets("target.process.id"))
            grouper1:feed(logline)
        end
    else
        if (logline:gets("target.object.name"):lower()):match("ntds%.dit$") then
            set_field_value(logline,"target.file.type", "active directory")
            
            if (logline:gets("target.object.name"):lower()):match("^\\device\\harddisk") then
                set_field_value(logline,"target.file.source_type", "shadowcopy")
            else
                set_field_value(logline,"target.file.source_type", "backup")
            end
        else
            set_field_value(logline,"target.file.type", "registry")
        end
        
        set_field_value(logline,"event.process.id", logline:gets("initiator.process.id"))
        grouper1:feed(logline)
    end
end

-- Функция группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec, log_registry_file, log_ntds_original, log_ntds_copy

    if unique_events > 1 then
        for _, event in ipairs(events) do
            if compare(event:gets("observer.event.id"), "==", "4688") then
                log_exec = event
            elseif event:gets("target.file.type") == "registry" then
                log_registry_file = event
            elseif event:gets("target.file.type") == "active directory" then
                if event:gets("target.file.source_type") == "shadowcopy" then
                    log_ntds_original = event
                else
                    log_ntds_copy = event
                end
            end
        end

        if (log_exec and log_registry_file) or (log_exec and log_ntds_original and log_ntds_copy) then
            local initiator_name = log_exec:gets("initiator.user.name")  
            local host_ip = log_exec:gets("observer.host.ip")
            local host_name = log_exec:gets("observer.host.hostname")
            local host_fqdn = log_exec:gets("observer.host.fqdn")
            local command_executed = string_cut(log_exec:gets("initiator.command.executed"))
            local process_path = (log_ntds_copy and log_ntds_copy:get("initiator.process.path.full")) or (log_registry_file and log_registry_file:get("initiator.process.path.full"))
            local target_file = (log_registry_file and log_registry_file:get("target.object.name") or (log_ntds_copy and log_ntds_copy:gets("target.object.name")))
            local source_object = (log_ntds_original and log_ntds_original:gets("target.object.name")) or log_exec:gets("target.object.name")
            local description = log_exec:gets("event.rule.description")

            alert({
               template = template,
               meta = {
                   title=description,
                   user=initiator_name,
                   command=command_executed,
                   path=process_path,
                   target_file=target_file,
                   source_object=source_object,
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
               mitre = {"T1003.003"},
               trim_logs = 10
               }
            )
            grouper1:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)