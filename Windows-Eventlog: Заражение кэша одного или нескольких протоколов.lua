-- Шаблоны алерта
local template1 = [[
Подозрение заражение кэша одного или нескольких протоколов.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{.Meta.command}}
Процесс: {{.Meta.process}}   
]]

local template2 = [[
Подозрение заражение кэша одного или нескольких протоколов.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Был изменен ключ реестра: {{ .Meta.key }}
Старое значение: {{ .Meta.old_value }}
Новое значение: {{ .Meta.new_value }}   
]]

-- Параметры группера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "event.type"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения, шаблоны
local new_value_prefixes = {"C:\\Users\\Public", "C:\\ProgramData", "C:\\ProgramFiles", "C:\\TMP", "C:\\Users"}
local new_value_suffix = "\\+\\S+\\.exe"
local old_value_patterns = {"-", "_", " ", ""}

local prefix = "(?:^|\\/|\\s+|\"|\'|\\\\)"
local command_patterns = { 
    prefix.. "schtasks(\\.exe)?(\\s+(\\/)?(?:create|onstart|system)[\\/\\s\\w]+){2,3}\\$?\\w:(\\\\[^\\\\ ]*)+\\\\?[-\\s\\w\\/\'\"]+",
    prefix.. "reg\\s+add\\s+(\\\\?[^\\\\ ]*)+\\\\?\\s+(\\/\\w+\\s+){1,5}[\'\"]{,1}[-.\\w]+[\'\"]{,1}\\s+\\/\\w+\\s+reg_sz\\s+\\/\\w+\\s+[\'\"]{,1}\\w:(\\\\[^\\\\ ]*)+\\\\?[\'\"]{,1}\\s+\\/\\w+"
}

-- Функция алерта
local function alert_function(type, template, events)
    local host_ip = event:get("observer.host.ip") or event:get("reportchain.collector.host.ip")
    local host_name = event:gets("observer.host.hostname", "Имя узла не определено")
    local host_fqdn = event:gets("observer.host.fqdn")
    local initiator_name = first_event:gets("initiator.user.name", "Пользователь не определён")
    local meta = {}

    if type == "command_meta" then
        local first_event = events[1]
        local service_name = first_event:gets("target.service.name", "Служба не определена") 
        local command_executed = first_event:gets("initiator.command.executed")
        local process_path = first_event:get("initiator.process.path.full") or first_event:get("initiator.process.path.name") or first_event:gets("event.logsource.application", "Путь неопределён")
        
        if #command_executed > 128 then
            command_executed = command_executed:sub(1, 128).. "... "
        end

        meta = {
            user_name=initiator_name,
            command=command_executed,
            process=process_path,
            service=service_name
        }
    elseif type == "registry_meta" then
        local object_name = first_event:gets("target.object.name")
        local config_new = first_event:gets("target.config.changes.new_value")
        local config_old = first_event:gets("target.config.changes.old_value")
        
        meta = {
            user_name=initiator_name,
            key=object_name,
            old_value=config_old,
            new_value=config_new
        }
    end
    
    alert({
            template = template,
            meta = meta,
            risk_level = 7.0, 
            asset_ip = ip,
            asset_hostname = hostname,
            asset_fqdn = fqdn,
            asset_mac = "",
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "",
            logs = events,
            mitre = {"1557.002"},
            trim_logs = 10
            }
        )
end

-- Стандартная функция анализа строки
local function analyze(string, type)
    local string = string:lower()
    --log("String: " ..string.. ", Type:" ..type)
    
    if type == "command" then
        for _, pattern in pairs(command_patterns) do
            local is_persistence = string:search(pattern) 

            if is_persistence then
                return true
            end
        end
    elseif type == "old_value" then
        local is_empty = contains(old_value_patterns, string)
    
        if is_empty then
            return true
        end
    elseif type == "new_value" then
        local is_prefix = contains(new_value_prefixes, string, "prefix") 
        local is_suffix = string:search(new_value_suffix)

        if is_suffix and is_prefix then 
            return true
        end
    end

    return false
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")

--    log("Event ID: " ..event_id)

    if event_id == 4657 then
        local changes_new_value = logline:gets("target.config.changes.new_value")
        local changes_old_value = logline:gets("target.config.changes.old_value")
        local is_empty_old = analyze(changes_old_value, "old_value")
        local is_empty_new = analyze(changes_new_value, "new_value")
       
--        log("Old value: " ..tostring(is_empty_old).. ", New value: " ..tostring(is_empty_new))

        if is_empty_new and is_empty_old then
            set_field_value(logline, "event.type", "registry_event")
            grouper1:feed(logline)
        end
    elseif event_id == 4688 or event_id == 4104 then
        local command_executed = logline:gets("initiator.command.executed")
        local is_persistence = analyze(command_executed, "command")

        if is_persistence then 
            set_field_value(logline, "event.type", "command_event")
            grouper1:feed(logline)
        end
    end  
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local command_events = {}
    local registry_events = {}

    log("Events: " ..#events)

    for _, event in ipairs(events) do
        local event_type = event:gets("event.type")
        
        if event_type == "command_event" then
            table.insert(command_events, event)
        else
            table.insert(registry_events, event)
        end

    end
    
    if #command_events > 0 then
        alert(template1, "command_meta", command_events)
        grouper:clear() 
    elseif #registry_event > 0 then
        alert(template2, "registry_meta", first_event)
        grouper1:clear()
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)