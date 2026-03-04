blacklist = storage.new("bl_system_users|Linux: Обнаружение запуска утилит передачи файлов от имени служебных учетных записей")
whitelist = storage.new("wl_hostnames|Linux: Обнаружение запуска утилит передачи файлов от имени служебных учетных записей")

-- Шаблон алерта
local template = [[
	Подозрение на запуск утилиты передачи файлов от имени служебных учетных записей.

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
local pattern = "(?:^|\\/|\\s+|\"|\')\\b(?:ftp|sftp|lftp|wget|scp|nc|rsync|curl|netcat)\\b(\\s+)?(-{1,2}[\\w=:\\-\\s]+)?"

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()
    local regular = cmd_string:search(pattern)
    
    if regular then
        return regular
    end
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    local initiator_command = logline:gets("initiator.command.executed")
    local path_name = logline:gets("initiator.process.path.name")
    local syscall_name = logline:gets("target.syscall.name")

    if event_type == "EXECVE" or event_type == "PROCTITLE" then
		local downloader = analyze(initiator_command)

        if downloader then
            grouper1:feed(logline)
		end
    elseif event_type == "SYSCALL" and syscall_name == "execve" then
        local app_path = analyze(path_name)
        if app_path then
            grouper1:feed(logline)
        end    
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_sys = nil
    local log_exec = nil

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_type = event:gets("observer.event.type")
            if event_type == "SYSCALL" then
                log_sys = event
            else
                log_exec = event
            end
        end

-- Проверяем, что в группере находятся как события EXECVE/PROCTITLE, так и SYSCALL
        if log_sys and log_exec then
            local initiator_name = log_sys:gets("initiator.user.name")
            local host_name = log_exec:gets("observer.host.hostname")

            check_blacklist = blacklist:get(initiator_name, "username")
            check_whitelist = whitelist:get(host_name, "hostname")
            
            if check_blacklist and check_whitelist ==nil then
                local host_ip = log_exec:gets("observer.host.ip")
                local host_fqdn = log_exec:gets("observer.host.fqdn")
                local path_name = log_sys:gets("initiator.process.path.full")
                local command_executed = log_exec:gets("initiator.command.executed")

                if #command_executed > 128 then
                    command_executed = command_executed:sub(1,128)
                end
-- Функция алерта
                alert({
                    template = template,
                    meta = {
                        user_name=initiator_name,
                        command=command_executed,
                        command_path=path_name
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
                    mitre = {"T1078"},
                    trim_logs = 10
                    }
                )
                grouper1:clear()      
            end
        end    
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)