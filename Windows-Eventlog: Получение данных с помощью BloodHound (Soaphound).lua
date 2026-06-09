-- Шаблон алерта
local template = [[
Обнаружена попытка дампа данных с использованием утилит SOAPHound, BloodHound или SharpHound.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{ .Meta.command }}
Выполненный скрипт/файл : {{ .Meta.script_name }}
Результирующий файл: {{ .Meta.file_name }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "event.process.id"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения, шаблоны
local hound_patterns = { "io.compression.deflatestream", "system.collections.generic.list[system.object]" }

-- Функция работы с логлайном
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")

    if compare(event_id, "==", "4103") then
        local object_name = logline:gets("target.object.name"):lower()
        
        if contains(hound_patterns, object_name, "sub") then
            local process_id = logline:gets("observer.process.id")
            set_field_value(logline, "event.process.id", process_id)
            grouper1:feed(logline)
        end
    elseif compare(event_id, "==", "4688") then
        local initiator_pid = nil
        local command_executed = logline:gets("initiator.command.executed"):lower()
        
        if command_executed:match("--buildcache") and (command_executed:match("--user") or command_executed:match("--dc")) then
            initiator_pid = logline:gets("target.process.id")
        else
            initiator_pid = logline:gets("initiator.process.parent.id")
        end
        
        set_field_value(logline, "event.process.id", initiator_pid)
        grouper1:feed(logline)
    elseif compare(event_id, "==", "4663") then
        local object_name = logline:gets("target.object.name")
        local initiator_pid = logline:gets("initiator.process.id")
        local file_name = object_name:match("[%d]+_[%w]+.zip")
    
        if file_name then
            local decimal_pid = tonumber(initiator_pid:gsub("^0[xX]", ""), 16)
            set_field_value(logline, "event.process.id", decimal_pid)
            grouper1:feed(logline)
        else
            set_field_value(logline, "event.process.id", initiator_pid)
            grouper1:feed(logline)
        end
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec = {}
    local log_file = nil
    local commands = {}
    local all_commands = nil

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")

            if compare(event_id, "==", "4103") or compare(event_id, "==", "4688") then
               table.insert(log_exec, event)
               local command_executed = event:gets("initiator.command.executed")
               table.insert(commands, command_executed)
            else
               log_file = event  
            end
        end

        if log_file and #log_exec > 0 then 
            local first_exec_event = log_exec[1]
            local initiator_name = first_exec_event:gets("initiator.user.name", "Пользователь не определён")  
            local host_ip = first_exec_event:get("observer.host.ip") or first_exec_event:gets("reportchain.collector.host.ip", "IP-адрес не определён")
            local host_name = first_exec_event:gets("observer.host.hostname", "Имя узла не определено")
            local host_fqdn = first_exec_event:gets("observer.host.fqdn", "FQDN узла не определено")
            
            if #commands > 1 then  
                all_commands = table.concat(commands, "; ")
            else
                all_commands = commands[1]
            end

            if #all_commands > 128 then
                all_commands = all_commands:sub(1, 128).. "... "
            end
            
            local script_path = first_exec_event:get("initiator.file.name") or first_exec_event:get("target.process.path.full") or first_exec_event:gets("initiator.process.parent.path.original", "Имя файла не определено")
            
            if script_path:match("^%d+$") then
                script_path = "Имя файла не определено"
            end

            local file_path = log_file:get("target.object.name")

            alert({
               template = template,
               meta = {
                   user_name=initiator_name,
                   command=all_commands,
                   script_name=script_path,
                   file_name=file_path,
                   host_ip=host_ip,
                   hostname=host_name
                   },
               risk_level = 6.0, 
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

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)