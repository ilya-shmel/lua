-- Шаблон алерта
local template = [[
	Подозрение на исчерпание ресурсов узла.
	Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]

-- Переменные для групперов
local detection_window = "3m"
local grouped_time_field = "@timestamp,RFC3339"
local grouped_by1 = {"observer.host.ip", "observer.host.hostname", "observer.event.type"}
local grouped_by2 = {"observer.host.ip", "observer.host.hostname", "event.result.name"}
local aggregated_by1 = {"observer.event.type"}
local aggregated_by2 ={"observer.service.name"}


--local syscall_ids = {"-28", "-24", "-23", "-12", "-122", "-27"}
local cpu_pattern = "cpu#\\d+\\s+stuck"

local function analyze(cmd)
    local cmd_string = cmd:lower()

    local check_pattern = cmd_string:search(cpu_pattern)
    
    if check_pattern then
        return check_pattern
    end
end

-- Функция алерта
local function alert_function(cmd,user,path,ip,hostname,fqdn, events)
    alert({
            template = template,
            meta = {
                user_name=user,
                command=cmd,
                command_path=path
                },
            risk_level = 8.0, 
            asset_ip = ip,
            asset_hostname = hostname,
            asset_fqdn = fqdn,
            asset_mac = "",
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "",
            logs = events,
            mitre = {"T1499.001", "T1499"},
            trim_logs = 10
            }
        )
end

-- Функция обработки логлайна
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    local service_name = logline:gets("observer.service.name")
    
    if event_type == "SYSCALL" then
        grouper1:feed(logline)
	end

    if service_name == "kernel" then
        local result_name = logline:gets("event.result.name")
        local kernel_command = logline:gets("initiator.command.executed")
        local is_cpu_stuck = analyze(result_name)
        
        if is_cpu_stuck or result_name == "out of memory" then
           grouper2:feed(logline)
        end
    
    end
end

-- Функция сработки группера
function on_grouped1(grouped)
	local events = grouped.aggregatedData.loglines
           
    if #events > 1 then
        local command_executed = events[1]:gets("initiator.process.path.name")
        local executed_path = events[1]:gets("initiator.process.path.full")
        local initiator_name = events[1]:gets("initiator.user.name")
        local host_ip = events[1]:gets("observer.host.ip")
        local host_name = events[1]:gets("observer.host.hostname")
        local host_fqdn = events[1]:gets("observer.host.fqdn") 

        alert_function(command_executed, initiator_name, executed_path, host_ip, host_name, host_fqdn, events)
        grouper1:clear()
    end    
end

function on_grouped2(grouped)
    local events = grouped.aggregatedData.loglines
    
    if #events > 1 then
        local command_executed = (events[1] and events[1]:gets("target.image.name"))
        local command_length=command_executed:len()
        
        if command_length < 1 then
            command_executed = "Команда не определена"
        end

        local executed_path = events[1]:gets("observer.service.name")
        local initiator_name = "Ядро операционной системы"
        local host_ip = events[1]:gets("observer.host.ip")
        local host_name = events[1]:gets("observer.host.hostname")
        local host_fqdn = events[1]:gets("observer.host.fqdn") 

        alert_function(command_executed, initiator_name, executed_path, host_ip, host_name, host_fqdn, events)
        grouper2:clear()
    end
end

-- Групперы
grouper1 =grouper.new(grouped_by1, aggregated_by1, grouped_time_field, detection_window, on_grouped1)
grouper2 =grouper.new(grouped_by2, aggregated_by1, grouped_time_field, detection_window, on_grouped2)