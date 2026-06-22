-- Шаблон алерта
local template = [[
Подозрение на запуск инструмента Mimikatz.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{ .Meta.command }}
Параметр команды: {{ .Meta.subcommand }}
Путь выполнения: {{ .Meta.parent }}
]]

-- Параметры группера #1
local detection_window1 = "30s"
local grouped_by1 = {"observer.host.ip", "observer.host.hostname", "initiator.command.type"}
local aggregated_by1 = {"initiator.command.executed"}

-- Параметры группера #2
local detection_window2 = "30s"
local grouped_by2 = {"observer.host.ip", "observer.host.hostname", "observer.process.id"}
local aggregated_by2 = {"observer.event.id"}

local grouped_time_field = "@timestamp,RFC3339"
-- Регулярные выражения, шаблоны

-- Функция работы с логлайном
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")

    if compare(event_id, "==", "4688") then
        local command_executed = logline:gets("initiator.command.executed"):lower()
        local command_parameter = command_executed:match("[%s\'\"]%w+::"):gsub("[%s:\'\"]", "") or "mimikatz"
        set_field_value(logline, "initiator.command.type", command_parameter)
        grouper1:feed(logline)
    elseif compare(event_id, "==", "4103") or compare(event_id, "==", "4104") then
        grouper2:feed(logline)
    end
end

-- Функция сработки группера #1
function on_grouped1(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total

    if #events > 0 then
        local first_event = events[1]
        local command_executed = first_event:gets("initiator.command.executed")
        local initiator_name = first_event:gets("initiator.user.name", "Пользователь не определён")
        local host_ip = first_event:get("observer.host.ip") or first_event:gets("reportchain.collector.host.ip", "IP-адрес узла не определён")
        local host_name = first_event:gets("observer.host.hostname", "Имя узла не определено")
        local host_fqdn = first_event:gets("observer.host.fqdn", "FQDN узла не определено")
        local parent_path = first_event:gets("initiator.process.parent.path.original")
        local subcommand = first_event:gets("initiator.command.type")
        
        if command_executed > 128 then
            command_executed = command_executed:sub(1, 128).. "... "
        end
            
        alert({
           template = template,
           meta = {
                user_name=initiator_name,
                command=command_executed,
                subcommand=subcommand,
                parent=parent_path,
                hostname=host_name,
                ip=host_ip
                },
           risk_level = 6.5, 
           asset_ip = host_ip,
           asset_hostname = host_name,
           asset_fqdn = host_fqdn,
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
       
        grouper1:clear()
    end
end

-- Функция сработки группера #2
function on_grouped2(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_scriptblock = {}
    local log_module = nil
    local functions = {}

    if unique_events > 0 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")

            if compare(event_id, "==", "4103") then
                log_module = event
            else
                table.insert(log_scriptblock, event)
                local command = event:gets("initiator.command.executed")
                table.insert(functions, command)
            end
        end

        if #log_scriptblock > 1 and log_module then
            local command_executed = log_module:gets("initiator.command.executed")
            local initiator_name = log_module:gets("initiator.user.name", "Пользователь не определён")
            local host_ip = log_module:get("observer.host.ip") or log_module:gets("reportchain.collector.host.ip", "IP-адрес узла не определён")
            local host_name = log_module:gets("observer.host.hostname", "Имя узла не определено")
            local host_fqdn = log_module:gets("observer.host.fqdn", "FQDN узла не определено")
            local all_functions = table.concat(functions, "; ")
                    
            if command_executed > 128 then
                command_executed = command_executed:sub(1, 128).. "... "
            end

            if all_functions > 128 then
                all_functions = all_functions:sub(1, 128).. "... "
            end
            
            alert({
               template = template,
               meta = {
                    user_name=initiator_name,
                    command=command_executed,
                    subcommand=all,
                    parent=parent_path,
                    hostname=host_name,
                    ip=host_ip
                    },
               risk_level = 6.5, 
               asset_ip = host_ip,
               asset_hostname = host_name,
               asset_fqdn = host_fqdn,
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
       
            grouper1:clear()
    
        end
    end
end


-- Групперы
grouper1 = grouper.new(grouped_by1, aggregated_by1, grouped_time_field, detection_window1, on_grouped1)
grouper2 = grouper.new(grouped_by2, aggregated_by2, grouped_time_field, detection_window2, on_grouped2)