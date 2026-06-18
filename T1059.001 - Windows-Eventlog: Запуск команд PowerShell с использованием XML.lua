-- Шаблон алерта
local template = [[
Обнаружена попытка запуска команды в PowerShell через XML-объекты.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{ .Meta.command }}
Скрытая команда: {{ .Meta.xml_command }}
Тип задействованного объекта: {{ .Meta.object }}
]]

-- Параметры группера #1
local detection_window1 = "30s"
local grouped_by1 = {"observer.host.ip", "observer.host.hostname", "observer.process.id"}
local aggregated_by1 = {"initiator.process.command"}

-- Параметры группера #2
local detection_window2 = "30s"
local grouped_by2 = {"observer.host.ip", "observer.host.hostname", "event.process.id"}
local aggregated_by2 = {"observer.event.id"}

local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения, шаблоны
local invoke_patterns = { "io.compression.deflatestream", "system.collections.generic.list[system.object]" }

-- Функция алерта
local function alert_function(ip, hostname, fqdn, user, cmd, xml_cmd, object, events, template)
--    log("Alert CMD: " .. cmd)
    alert({
            template = template,
            meta = {
                user_name=user,
                command=cmd,
                xml_command=xml_cmd,
                object=object,
                host_ip=ip,
                hostname=hostname
                },
            risk_level = 6.0, 
            asset_ip = ip,
            asset_hostname = hostname,
            asset_fqdn = fqdn,
            asset_mac = "",
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "",
            logs = events,
            mitre = {"T1059.001"},
            trim_logs = 10
            }
        )
end

-- Функция выделения уникальных значений в таблице
local function unique_elements(commands_table)
    local seen = {}
    local result = {}
    
    for _, element in ipairs(commands_table) do
        if not seen[element] then
            seen[element] = true
            table.insert(result, element)
        end
    end

    return result
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")

    if compare(event_id, "==", "4688") then
        local target_pid = logline:gets("target.process.id")
        local process_id = tonumber(target_pid:gsub("^0[xX]", ""), 16) -- Преобразование из шестнадцатеричной системы в десятичную
        set_field_value(logline, "event.process.id", process_id)
        grouper2:feed(logline)
    elseif compare(event_id, "==", "4103") then
        local object_name =  logline:gets("target.object.name"):lower()

        if object_name:find("msxml2") or object_name:find("serverxmlhttp") then
            local process_id = logline:gets("observer.process.id")
            set_field_value(logline, "event.process.id", process_id)
            grouper2:feed(logline)        
        else
            grouper1:feed(logline)
        end
    end
end

-- Функция сработки группера
function on_grouped1(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec = nil
    local log_object = nil
    local commands = {}
    local all_commands = nil

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local cmdlet = event:gets("initiator.process.command"):lower()
            local command_executed = event:gets("initiator.command.executed")
            local object_name = event:gets("target.object.name"):lower()
            table.insert(commands, command_executed)

            if compare(cmdlet, "==", "new-object") and object_name:search("(system\\.)?(xml\\.)?xmldocument") then
                log_object = event
            elseif compare(cmdlet, "==", "invoke-expression") then
                log_exec = event
            end
        end

        if log_object and log_exec then 
            commands = unique_elements(commands)
            all_commands = table.concat(commands, "; ")
            
              if #all_commands > 128 then
                all_commands = all_commands:sub(1, 128).. "... "
            end
            
            local initiator_name = log_exec:gets("initiator.user.name", "Пользователь не определён")  
            local host_ip = log_exec:get("observer.host.ip") or log_exec:gets("reportchain.collector.host.ip", "IP-адрес не определён")
            local host_name = log_exec:gets("observer.host.hostname", "Имя узла не определено")
            local host_fqdn = log_exec:gets("observer.host.fqdn", "FQDN узла не определено")
            local xml_command = log_exec:gets("target.object.name")
            local object_name = log_object:gets("target.object.name")
            alert_function(host_ip, host_name, host_fqdn, initiator_name, all_commands, xml_command, object_name, events, template)
            grouper1:clear()
        end
    end
end

function on_grouped2(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec = nil
    local log_module = nil

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")
            
            if compare(event_id, "==", "4688") then
                log_exec = event
            else
                log_module = event
            end
        end

        if log_module and log_exec then 
            local command_executed = log_exec:gets("initiator.command.executed")
            local initiator_name = log_module:gets("initiator.user.name", "Пользователь не определён")  
            local host_ip = log_exec:get("observer.host.ip") or log_exec:gets("reportchain.collector.host.ip", "IP-адрес не определён")
            local host_name = log_exec:gets("observer.host.hostname", "Имя узла не определено")
            local host_fqdn = log_exec:gets("observer.host.fqdn", "FQDN узла не определено")
            local xml_command = log_module:gets("initiator.command.executed")
            local object_name = log_module:gets("target.object.name")
            
            if #command_executed > 128 then
                command_executed = command_executed:sub(1, 128).. "... "
            end

            alert_function(host_ip, host_name, host_fqdn, initiator_name, command_executed, xml_command, object_name, events, template)
            grouper2:clear()
        end
    end
end

-- Группер
grouper1 = grouper.new(grouped_by1, aggregated_by1, grouped_time_field, detection_window1, on_grouped1)
grouper2 = grouper.new(grouped_by2, aggregated_by2, grouped_time_field, detection_window2, on_grouped2)