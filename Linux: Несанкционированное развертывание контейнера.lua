whitelist = storage.new("container_users|Linux: Несанкционированное развертывание контейнера")

-- Шаблоны алерта
local template = [[
	Подозрение на несанкционированное развертывание контейнера.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]

-- Переменные для групера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

local container_pattern = "(?:docker|podman|nerdctl|lxc)(-compose)?\\s+(?:run|build|exec|compose|pull|up|play|generate|pod|launch)\\s+[-\\w\\s:=\\/\\.\"\']+"


-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()
    local is_container = cmd_string:search(container_pattern)
    
    if is_container then
        return is_container
    end
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    
    if event_type == "EXECVE" or event_type == "PROCTITLE" then
        local command_executed = logline:gets("initiator.command.executed")
		local container_running = analyze(command_executed)
        
        if container_running then
            grouper1:feed(logline)
        end
    else
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_sys = nil
    local log_exec = nil

    for _, event in ipairs(events) do
        if event:gets("observer.event.type") == "SYSCALL" then
            log_sys = event
        else
            log_exec = event
        end
    end

-- Проверяем, что в группере находятся как события EXECVE/PROCTITLE, так и SYSCALL        
    if log_sys and log_exec then
        local host_name = log_exec:gets("observer.host.hostname")
        
        if whitelist:get(host_name, "hostname") == nil then                
            local host_ip = log_exec:gets("observer.host.ip")
            local host_fqdn = log_exec:gets("observer.host.fqdn")
            local initiator_name = log_sys:gets("initiator.user.name")
            local path_name = log_sys:gets("initiator.process.path.full")
            local command_executed = log_exec:gets("initiator.command.executed")
            
            if #command_executed > 128 then
                command_executed = command_executed:sub(1,128).. "..."
            end
            -- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command=command_executed,
                    command_path=path_name
                    },
                risk_level = 9.0, 
                asset_ip = host_ip,
                asset_hostname = host_name,
                asset_fqdn = host_fqdn,
                asset_mac = "",
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                logs = grouped.aggregatedData.loglines,
                mitre = {"T1610", "T1612"},
                trim_logs = 10
                }
            )
            grouper1:clear()      
        end
    end    
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)