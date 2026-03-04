-- Linux: Обнаружена сетевая разведка
local template = [[
    Обнаружена сетевая разведка.
    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]


local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"


-- Регулярное выражение
local process_pattern = "(?:^|\\s+|\\/|\\|\"|\'|\\n)((?:z|n)map||(?:mas|arp-|ssl)scan|netdiscover|arp\\s+-a|ip\\s+neigh\\s+show|nikto|dirb|n(et)?c(at)?|(?:h|f)?ping\\d?|traceroute|netstat|ss)(?:$|\\s+|\\/|\\.|\'|\"|\\,|\\|\\n)"

local function analyze(cmd)
    local regular = cmd:lower():search(process_pattern)   
    
    if regular then
        return true
    end
    
    return false
end


function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    
    if event_type == "EXECVE" or event_type == "PROCTITLE" then
        local command = logline:gets("initiator.command.executed")
        if command then
            local result = analyze(command)
            if result then
                grouper1:feed(logline)
            end
        end
    elseif event_type == "SYSCALL" then
        grouper1:feed(logline)
    end
end


function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_sys = nil
    local log_exec = nil

    -- Разделяем события на SYSCALL и EXECVE/PROCTITLE
    for _, event in ipairs(events) do
        if event:gets("observer.event.type") == "SYSCALL" then
            log_sys = event
        elseif event:gets("observer.event.type") == "EXECVE" or event:gets("observer.event.type") == "PROCTITLE" then
            log_exec = event
        end
    end
    
    -- Проверяем наличие обоих типов событий
    if log_sys and log_exec then
        local command = log_exec:gets("initiator.command.executed")
        
        -- Дополнительная проверка команды
        if analyze(command) then
            
            -- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name = log_sys:gets("initiator.user.name") or "Не определен",
                    command = command,
                    command_path = log_sys:gets("initiator.process.path.full") or "Не определен",
                },
                risk_level = 9.0, 
                asset_ip = log_exec:get_asset_data("observer.host.ip"),
                asset_hostname = log_exec:get_asset_data("observer.host.hostname"),
                asset_fqdn = log_exec:get_asset_data("observer.host.fqdn"),
                asset_mac = "",
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                logs = events,
                mitre = {"T1046"},
                trim_logs = 10
            })

        end
    end
end


grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)
