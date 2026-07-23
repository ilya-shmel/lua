-- Шаблон алерта
local template = [[
Подозрение на хищение паролей и имён пользователей с помощью библиотеки NPPSpy.dll.

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{ or .Meta.ip "IP-адрес не определён" }}
Узел: {{ or .Meta.hostname "Имя узла не определено" }}
FQDN: {{ or .Meta.fqdn "FQDN узла не определено" }}

ИНИЦИАТОР:
Пользователь: {{ or .Meta.user "Пользователь не определён"}}

ВЫПОЛНЕННАЯ КОМАНДА:
{{ .Meta.command }}
Затронутые объекты/файлы: {{ .Meta.object }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "observer.process.id"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local npp_patterns = {
    [[(?:^|[\\;\s"'(])(?:invoke-webrequest|iwr)[\\\s"'\)]?([\s\S]*)?[\/"]nppspy(\.dll)?(?:;|}|\s+|\))]],
    [[copy-item\s+([\s\S]*)?nppspy\.dll(?:"|'|\s+)([\s\S]*)?(?:"|'|\s+)c:\\windows\\[^\\"']*(?:"|'|\s+|;|$)*]],
    [[-path\s+['"]?hklm:\\system\\currentcontrolset\\services\\nppspy(?:\s+|\\|'|"|$)]],
    [[\s+-value\s+['"]?%systemroot%\\system32\\nppspy\.dll['"]?(?:\s+|$)]]
}

-- Вспомогательная функция логирования значений в группере (удалить после тестирования на потоке)
local function log_grouper(events, events_number, unique_events, grouper_name, grouper_field)
    log("### " .. grouper_name .. " ###")
    log("Events: " ..#events.. ". Unique events: " ..unique_events)
    
    for _, event in ipairs(events) do
	    log("Event ID: " .. tostring(event:gets("observer.event.id")))
        log("Grouper field: " .. tostring(event:gets(grouper_field))) 
    end    
end

-- Функция алерта
local function alert_function(events, ip, hostname, fqdn, user, cmd, object)
    alert({
        template = template,
        meta = {
            user=user,
            command=cmd,
            path=path,
            object=object,
            ip=ip,
            hostname=hostname,
            fqdn=fqdn
            },
        risk_level = 4.0, 
        asset_ip = ip,
        asset_hostname = hostname,
        asset_fqdn = fqdn,
        asset_mac = "",
        create_incident = true,
        incident_group = "",
        assign_to_customer = false,
        incident_identifier = "",
        logs = events,
        mitre = {"T1003.004"},
        trim_logs = 10
        }
     )
end

-- Функция сокращения строки для алерта
local function string_cut(cmd)
    if #cmd > 256 then
        cmd = cmd:sub(1, 256).. "... "
    end

    return cmd
end

-- Функция анализа строки по регулярному выражению
local function analyze(cmd)
    local cmd_lower = cmd:lower()
    for _, pattern in ipairs(npp_patterns) do
        if cmd_lower:search(pattern) then
            return true
        end
    end
    return false
end

-- Функция обработки логлайна
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")

    if compare(event_id, "==", "4104") then
        local command_executed = logline:gets("initiator.command.executed")
        
        if analyze(command_executed) then
            grouper1:feed(logline)
        end
    else
        grouper1:feed(logline)
    end
end

-- Функция группера #1
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_scriptblock = {}
    local log_module = {}
    local commands = {}
    local objects = {}
    
    log_grouper(events, #events, unique_events, "on_grouped", grouped_by[4])

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")

            if compare(event_id, "==", "4104") then
                table.insert(log_scriptblock, event)
                table.insert(commands, event:gets("initiator.command.executed"))
            else
                table.insert(log_module, event)
                table.insert(objects, event:gets("target.object.name"))
            end
        end

        if #log_scriptblock > 0 and #log_module > 1 then
            local first_scriptblock_event = log_scriptblock[1]
            local first_module_event = log_module[1]
            local initiator_name = first_module_event:gets("initiator.user.name")  
            local host_ip = first_scriptblock_event:get("observer.host.ip")
            local host_name = first_scriptblock_event:gets("observer.host.hostname")
            local host_fqdn = first_scriptblock_event:gets("observer.host.fqdn")
            local command_executed = string_cut(table.concat(commands, "; "))
            local objects = string_cut(table.concat(objects, "; "))

            alert_function(events, host_ip, host_name, host_fqdn, initiator_name, command_executed, objects)
            grouper1:clear()
        end

    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)