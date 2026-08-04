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
Имя программы: {{ .Meta.program }}
Процесс/Путь к иcполняемому файлу: {{ .Meta.path }}
Родительский процесс: {{ .Meta.parent }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by1 = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "event.auth.logon.id"}
local grouped_by2 = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "initiator.process.command"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Вспомогательная функция логирования значений в группере (удалить после тестирования на потоке)
local function log_grouper(events, events_number, unique_events, grouper_name, grouper_field)
    log("### " .. grouper_name .. " ###")
    log("Events: " ..#events.. ". Unique events: " ..unique_events)
    
    for _, event in ipairs(events) do
        local event_id = event:gets("observer.event.id")
        log("Event ID: " .. tostring(event_id) .. ". Grouper field: " .. tostring(event:gets(grouper_field)))
        
        if event_id == 4688 then 
            local command_executed = event:gets("initiator.command.executed")
            log("Command executed: " .. command_executed)
        else
            local process_path = event:gets("target.process.path.original")
            log("Process path: " ..process_path)
        end
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

-- Функция обработки логлайна
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")

    if compare(event_id, "==", "4688") then
        local command_executed = logline:gets("initiator.command.executed"):lower()
        if command_executed:search("(?:excel|word|prpnt|outlook).application") then 
            set_field_value(logline,"initiator.process.command", command_executed:match("(%w+)%.application")) 
            grouper2:feed(logline)
        else
            set_field_value(logline, "event.auth.logon.id", logline:gets("initiator.auth.logon.id"))
            grouper1:feed(logline)
        end
    else
        set_field_value(logline, "event.auth.logon.id", logline:gets("target.auth.logon.id"))
        grouper1:feed(logline)
    end
end

-- Функция группера #1
function on_grouped1(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_mask, log_target, log_logon
--    log_grouper(events, #events, unique_events, "on_grouped1", grouped_by1[4])

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")
            local initiator_path = event:gets("initiator.process.parent.path.original"):lower()

            if compare(event_id, "==", "4688") then
                if initiator_path:find("microsoft office\\root\\office") then
                    log_mask = event
                else 
                    log_target = event
                end
            else
                log_logon = event
            end
        end
        
        if log_mask and log_target and log_logon then
            local process_path = log_mask:gets("initiator.process.parent.path.original"):lower()
            local process_command = (process_path):match("(%w+)%.exe$")
            local target_process_command = log_target:gets("initiator.command.executed")
            set_field_value(log_mask,"initiator.process.command", process_command)
            set_field_value(log_mask,"target.process.command", target_process_command)
            set_field_value(log_target,"initiator.process.command", process_command)
            set_field_value(log_logon,"initiator.process.command", process_command)
            grouper2:feed(log_mask)
            grouper2:feed(log_target)
            grouper2:feed(log_logon)
            grouper1:clear()
        end
    end
end

-- Функция группера #2
function on_grouped2(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec, log_mask
    local log_task = {}
    log_grouper(events, #events, unique_events, "on_grouped2", grouped_by2[4])
    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")
            local initiator_path = event:gets("initiator.process.parent.path.original"):lower()
            local target_image = event:gets("target.image.name"):lower()

            if compare(event_id, "==", "4688") then
                if initiator_path:find("microsoft office\\root\\office") then
                    log_mask = event
                elseif target_image:find("powershell.exe") or target_image:find("pwsh.exe") or target_image:find("cmd.exe") then
                    log_exec = event
                else
                    table.insert(log_task, event)
                end
            else
                table.insert(log_task, event)
            end
        end

        if log_exec and log_mask and #log_task > 1 then
            local meta = {
                user=log_exec:gets("initiator.user.name"),
                command=string_cut(log_exec:gets("initiator.command.executed")),
                path=log_exec:gets("target.process.path.full"),
                program=log_mask:gets("target.process.command"),
                parent=log_mask:gets("target.image.name"),
                ip=log_exec:gets("observer.host.ip"),
                hostname=log_exec:gets("observer.host.hostname"),
                fqdn=log_exec:gets("observer.host.fqdn"),
                risk = 7.5,
                title = "Подозрение на латеральное перемещение с помощью MS Office"
            }

            alert_function(events, meta)
            grouper2:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by1, aggregated_by, grouped_time_field, detection_window, on_grouped1)
grouper2 = grouper.new(grouped_by2, aggregated_by, grouped_time_field, detection_window, on_grouped2)