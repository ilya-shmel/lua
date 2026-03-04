-- Шаблон алерта
local template = [[
	Обнаружен запуск инструмента linpeas.sh для получения информации о системе.  

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Выполненные команды: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]

-- Переменные для групера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

log_sys = {}
log_exec = {}
commands_executed = {}

-- Массив с регулярными выражениями
local prefix = "(?:\\/|\\.\\/|\\s+|^)"
local command_patterns = { 
    prefix .. "(?:\\/|\\.\\/|\\s+|^)find\\s+(\\/(?:usr|srv|snap|sbin|private|cdrom|applications|home|lib|media|mnt|opt|private|)?){1,10}\\s+[-\\s\\w\\.\\*\\/!\\(\\)=]{100,999}", 
    prefix .. "find\\s+\\/(?:sys(tem(d)?)?|run)\\s+[-\\w\\*\\s\\.]{45,255}",
    prefix .. "grep\\s+-(?:e|q|ev|i)\\s+[\\,\\-\\w\\s\\/\\|\\.$=^*]+",
    prefix .. "sed\\s+(?:\"|\')?s,[\\s\\w\\/!]+,[\\s\\S]\\[[,;\\w&]+[\\s\\S][\\[\\w,]+(?:\"|\')?"
}

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()
    
    for _, pattern in ipairs(command_patterns) do
        local is_script = cmd_string:search(pattern)

        if is_script then
            return is_script
        end
    end
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    local pid = logline:gets("observer.event.id") or "nil"
    if event_type == "EXECVE" then
        local command_executed = logline:gets("initiator.command.executed")
		local script_marker = analyze(command_executed)
        
        if script_marker then
            grouper1:feed(logline)
        end
    elseif event_type == "SYSCALL" then
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
      
    if unique_events > 1 then
        for _, event in ipairs(events) do
            event_type = event:gets("observer.event.type") 
            if event_type == "SYSCALL" then
                table.insert(log_sys, event)
            else
                table.insert(log_exec, event)

            end
        end

-- Проверяем, что в группере находятся как события EXECVE, так и SYSCALL        
            if #log_sys > 15 and #log_sys > 15 then
                local host_ip = log_exec[1]:gets("observer.host.ip")
                local host_fqdn = log_exec[2]:gets("observer.host.fqdn")
                local initiator_name = log_sys[1]:gets("initiator.user.name")
                local path_name = log_sys[1]:gets("initiator.process.path.full")
                local user_name = log_sys[1]:gets("initiator.user.name")
                
-- Объединить все зафиксированные команды в одну строку и обрезать её для наглядного вывода в карточке инцидента                
                for index = 1, #log_exec do
                    local current_command = log_exec[index]:gets("initiator.command.executed")
                    if #current_command > 63 then
                    current_command = current_command:sub(1,63).. "... "
                end 
                    commands_executed[index] = current_command 
                end

                local all_captured_commands = table.concat(commands_executed, "; ")
                
-- Функция алерта
                alert({
                    template = template,
                    meta = {
                        user_name=initiator_name,
                        command_path=path_name,
                        command=all_captured_commands
                    },
                    risk_level = 7.0, 
                    asset_ip = host_ip,
                    asset_hostname = host_name,
                    asset_fqdn = host_fqdn,
                    asset_mac = "",
                    create_incident = true,
                    incident_group = "",
                    assign_to_customer = false,
                    incident_identifier = "",
                    command=command_executed,
                    logs = grouped.aggregatedData.loglines,
                    mitre = {"T1082","T1087"},
                    trim_logs = 50
                    }
                )
                grouper1:clear()      
            end
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)