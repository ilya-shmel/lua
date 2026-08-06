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
Имя файла: {{ .Meta.file }}
Имя архива: {{ .Meta.archive }}
Процесс/Путь к иcполняемому файлу: {{ .Meta.path }}
Родительский процесс: {{ .Meta.parent }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "target.object.path.name"}
local aggregated_by = {"operation.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Шаблоны и паттерны
local archivator_pattern = [=[[(?:^|\s+|"|'|\\)(?:(win)?rar|7z|(?:win|wzun)zip|tar)[\\\s"'\:;)]]=]
local target_path_pattern = "(%a:\\[^\"\']+)\\[^\"\']+%.[excmdps1batvbsj]+$"
local shells = {"cmd.exe", "powershell.exe", "pwsh.exe"}
local extentions = {".exe", ".bat", ".ps1", ".vbs", ".js", ".cmd"}

-- Вспомогательная функция логирования значений в группере (удалить после тестирования на потоке)
local function log_grouper(events, events_number, unique_events, grouper_name, grouper_field)
    log("### " .. grouper_name .. " ###")
    log("Events: " ..#events.. ". Unique events: " ..unique_events)
    
    for _, event in ipairs(events) do
	    log("Event ID: " .. tostring(event:gets("observer.event.id")))
        log("Grouper field: " .. tostring(event:gets(grouper_field))) 
    end    
end

-- Логируем по EventID
local function log_on_logline(event)
    local event_id = event:gets("observer.event.id")
    log("###  on_logline  ###")
        
    if compare(event_id, "==", "4688") then
        log("Event ID: " .. tostring(event_id))
        local command_executed = event:gets("initiator.command.executed")
        local target_path = command_executed:match(target_path_pattern)
        local image_name = event:gets("target.image.name"):lower()
        log("Command: " .. command_executed:lower())
        log("Target pattern: " .. target_path_pattern .. ". Target path: " .. tostring(target_path))
        log("Command regex result: " .. tostring(command_executed:lower():search(archivator_pattern)))
    end
end

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

-- Функция отправки в группер
local function send_to_grouper(event, target_path, operation_type)
    set_field_value(event, "target.object.path.name", target_path)
    set_field_value(event, "operation.type", operation_type)
    grouper1:feed(event)
end

-- Функция обработки логлайна
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")

--    log_on_logline(logline)

    if compare(event_id, "==", "4688") then
        local command_executed = logline:gets("initiator.command.executed")
        local command_lower = command_executed:lower()
        local target_path = command_executed:match(target_path_pattern)
        local image_name = logline:gets("target.image.name"):lower()
        
        if command_lower:search(archivator_pattern) and target_path then
            send_to_grouper(logline, target_path, "expand archive")
        elseif contains(shells, image_name) and contains(extentions, command_lower, "sub") and target_path then
            send_to_grouper(logline, target_path, "run archive")
        end
    else
        if #(logline:gets("initiator.command.executed")) == 0 then
            local target_path = (logline:gets("raw"):lower()):match("\"DestinationPath\";%s+value=\"([%w:.\\]*)\"")
            set_field_value(logline, "target.object.path.name", target_path)
        end
        
        set_field_value(logline, "operation.type", "expand archive")
        grouper1:feed(logline)
    end
end

-- Функция группера #1
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec, log_extract
    
    log_grouper(events, #events, unique_events, "on_grouped", grouped_by[4])

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local operation_type = event:gets("operation.type")

            if operation_type == "run archive" then
                log_exec = event
            else
                log_extract = event
            end
        end

        if log_exec and log_extract then 
            local meta = {
                user=log_exec:gets("initiator.user.name"),
                command=string_cut(log_exec:gets("initiator.command.executed")),
                path=log_exec:gets("target.process.path.full"),
                file=log_exec:gets("target.object.path.name"),
                archive=log_extract:gets("target.object.path.name"),
                parent=log_exec:gets("initiator.process.parent.path.original"),
                ip=log_extract:gets("observer.host.ip"),
                hostname=log_extract:gets("observer.host.hostname"),
                fqdn=log_extract:gets("observer.host.fqdn"),
                risk=6.0,
                mitre={"T1036"},
                title="Подозрение на выполнение нелегитимных программ из архивов"
        }
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)