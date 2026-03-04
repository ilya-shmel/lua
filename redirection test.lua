-- Шаблон алерта
local template = [[
	Подозрение на очистку журналов аудита с помощью системных утилит.

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

-- Массив с регулярными выражениями
local proctitle_pattern = "^-[a-z]{1,2}sh"
local path_pattern = "(?:\\/var\\/(?:log|lib)|(?:~|[\\/\\w\\-_]+\\/home|\\/root)\\/\\.(?:local\\/share|cache|config)|\\/(?:opt|srv)[\\/\\w\\-_\\*]+\\/log(s))(\\/[\\/\\w\\-_\\*]+(\\.log)?)?"

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd,pattern)
    local cmd_string = cmd:lower()
    local regular = cmd_string:search(pattern)
    if regular then
        return regular
    end
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    local object_type = logline:gets("target.object.type")
    local command_executed = logline:gets("initiator.command.executed")
    local path_full = logline:gets("target.object.path.full")
    local syscall_name = logline:gets("target.syscall.name")

    if  event_type == "PROCTITLE" then
		local search_proctitle = analyze(command_executed,proctitle_pattern)
        if search_proctitle then
            grouper1:feed(logline)
		end
    end

    if  event_type == "PATH" and object_type == "normal" then
        local search_path = analyze(path_full,path_pattern)
        if search_path then
            grouper1:feed(logline)
		end        
    end

    if  event_type == "SYSCALL" and syscall_name == "openat" then
        


end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local log_sys = ""
    local log_exec = ""

    for _, event in ipairs(events) do
        if event:gets("observer.event.type") == "SYSCALL" then
            log_sys = event
        else
            log_exec = event
        end
    end

-- Проверяем, что в группере находятся как события EXECVE/PROCTITLE, так и SYSCALL        
    if log_sys ~= "" and log_exec ~= "" then
        local command_executed=log_exec:gets("initiator.command.executed")
        local command_length=command_executed:len().. "..."
        if command_length > 128 then
            command_executed=command_executed:sub(1,128)
        end
        -- Функция алерта
        alert({
            template = template,
            meta = {
                user_name=log_sys:gets("initiator.user.name"),
                command=command_executed,
                command_path=log_sys:gets("initiator.process.path.full")
                },
            risk_level = 8.0, 
            asset_ip = log_exec:get_asset_data("observer.host.ip"),
            asset_hostname = log_exec:get_asset_data("observer.host.hostname"),
            asset_fqdn = log_exec:get_asset_data("observer.host.fqdn"),
            asset_mac = "",
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "",
            logs = grouped.aggregatedData.loglines,
            mitre = {"T1070.002"},
            trim_logs = 10
            }
        )
        grouper1:clear()      
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)