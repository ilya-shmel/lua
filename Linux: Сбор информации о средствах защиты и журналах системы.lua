-- Шаблон алерта
local template = [[
	Подозрение на сбор информации о средствах защиты и журналах системы. 

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
local prefix = "(?:^|\\/|\\s+|\"|\')?"
local suffix = "(?:$|\\/|\\s+|\"|\'|;)?"
local app_pattern = "(?:\"|\')?((?:bareos-fd|icinga2|cbagentd|wazuh-agent|packetbeat|filebeat|osqueryd|falcond|nessusd|cbagentd|td-agent|auditbeat|auditd)\\|?)+(?:\"|\')?"
local command_patterns = { 
    prefix .. "systemctl\\s+status\\s+" .. app_pattern .. "(\\.service)?" .. suffix,
    prefix .. "(?:p|e)?grep\\s+(-{1,2}[\\w\\s=:]+){0,10}(?:\'|\")?(?:" .. app_pattern .. "|pid=\\d+)(?:\'|\")?" .. suffix,
    prefix .. "readlink\\s+(-[\\w=:]\\s+)+\\/proc\\/\\d+\\/exe" .. suffix,
    prefix .. app_pattern .. "\\s+-{1,2}v(ersion)?(\\s+[\\d>&]+)?" .. suffix,
    prefix .. "journalctl\\s+-{1,2}[\\w=\\-:]+\\s+" .. app_pattern .. "(\\.service)?\\s+-{1,2}[\\w=\\-:\\s]+" .. suffix,
    prefix .. "find\\s+(\\/(?:etc|opt|usr)\\s+){1,3}-{1,2}[\\w=\\-:\\s]+(?:\'|\")" .. app_pattern .. "(?:\'|\")\\s+[\\w>\\/]+" .. suffix,
    prefix .. "journalctl\\s+(-{1,2}(?:disk-usage|verify|b|1)\\s+){1,2}(--no-pager\\s+[-\\w\\s]+)" .. suffix,
    prefix .. "find\\s+\\/var\\/log\\s+[\\-,\\,\\w\\s\\/+\'\"%]+(>\\/dev\\/\\w+)?" .. suffix,
    prefix .. "ls\\s+-{1,2}\\w+(\\s+\\/etc\\/(?:r?syslog(?:\\*|-ng\\*|\\.d|-ng\\.d)|logrotate\\.d))+" .. suffix,
    prefix .. "systemctl\\s+status\\s+((?:(r)?syslog(-ng)?|systemd-journald)\\.service(\\s+)?)+" .. suffix,
    prefix .. "du\\s+[-\\w=:\\s]+(\\s+\\/var\\/log\\/[^\\s\\/]+)+"  .. suffix,
    prefix .. "cat\\s+\\/etc\\/logrotate\\.conf"  .. suffix,
    prefix .. "tail\\s+-\\w\\s+\\d+\\s+\\/var\\/log\\/(audit\\/)?(?:syslog|messages|auth\\.log|secure|kern\\.log|audit\\.log)" .. suffix
    }


-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()
        
    for _, pattern in ipairs(command_patterns) do
        local regular = cmd_string:search(pattern)
    
        if regular then
            return regular
        end
    end
end

-- Функция работы с логлайном
function on_logline(logline)
    if logline:gets("observer.event.type") == "EXECVE" or logline:gets("observer.event.type") == "PROCTITLE" then
		local obtain_marker = analyze(logline:gets("initiator.command.executed"))
        if obtain_marker then
            grouper1:feed(logline)
		end
    else
        grouper1:feed(logline)
    end
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

    local user_name = log_sys:gets("initiator.user.name")
    
-- Проверяем, что в группере находятся как события EXECVE/PROCTITLE, так и SYSCALL        
        if log_sys ~= "" and log_exec ~= "" then
            local host_ip = log_exec:gets("observer.host.ip")
            local host_fqdn = log_exec:gets("observer.host.fqdn")
            local initiator_name = log_sys:gets("initiator.user.name")
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
                    command_path=path_name,
                    command=command_executed
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
                command=command_executed,
                logs = grouped.aggregatedData.loglines,
                mitre = {"T1518.001"},
                trim_logs = 10
                }
            )
            grouper1:clear()      
        end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)