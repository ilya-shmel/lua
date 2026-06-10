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

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.process.id"}
local aggregated_by = {"initiator.process.command"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения, шаблоны
local invoke_patterns = { "io.compression.deflatestream", "system.collections.generic.list[system.object]" }


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
    grouper1:feed(logline)
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec = nil
    local log_object = nil
    local commands = {}
    local all_commands = nil

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local cmdlet = event:gets("initiator.process.command"):lower()
            local command_executed = event:gets("initiator.commands.executed")
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
            local initiator_name = log_exec:gets("initiator.user.name", "Пользователь не определён")  
            local host_ip = log_exec:get("observer.host.ip") or log_exec:gets("reportchain.collector.host.ip", "IP-адрес не определён")
            local host_name = log_exec:gets("observer.host.hostname", "Имя узла не определено")
            local host_fqdn = log_exec:gets("observer.host.fqdn", "FQDN узла не определено")
            local xml_command = log_exec:get("target.object.name")
            local object_name = log_object:get("target.object.name")

            alert({
               template = template,
               meta = {
                   user_name=initiator_name,
                   command=all_commands,
                   xml_command=xml_command,
                   object=object_name,
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