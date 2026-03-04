-- Шаблон алерта
local template = [[
	Подозрение на несанкционированную модификацию/добавление задач в cron.
    На узле: {{ if .First.observer.host.ip }}"{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }} - {{ if .First.observer.host.hostname }}"{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }},
    Пользователем: {{ .Meta.user_name }},
    Была выполнена команда: {{ .Meta.command }},
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}.
]]

-- Переменные для групера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Массив с регулярными выражениями
local crontab_pattern = "(?:^|\\/|\\s+|\"|\')crontab\\s+((-{1,2}[\\w=\\,\\s\\.]+){0,10})?((\\/?[^\\/ ]*)+\\/?)(?:$|\\/|\\s+|\"|\')"

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    if not cmd then
        return false
    end

    local cmd_string = cmd:lower()

    local regular = cmd_string:search(crontab_pattern)
--        log(cmd_string)
    if regular then
        return regular
    end
end

-- Функция работы с логлайном
function on_logline(logline)
    if not logline then
        return
    end

    if logline:gets("observer.event.type") == "SYSCALL" and logline:gets("initiator.process.path.full") == "/usr/bin/crontab" and logline:gets("target.syscall.name") == "openat" then
        local syscall_openat_id = logline:gets("observer.event.id")
        grouper1:feed(logline)
    end

    if logline:gets("observer.event.type") == "SYSCALL" and logline:gets("initiator.process.path.full") == "/usr/bin/crontab" and logline:gets("target.syscall.name") == "execve" then
        local syscall_execve_id = logline:gets("observer.event.id")
        grouper1:feed(logline)
    end    

    if logline:gets("observer.event.type") == "EXECVE" or logline:gets("observer.event.type") == "PROCTITLE" then
		local search_crontab = analyze(logline:gets("initiator.command.executed"))
        if search_crontab then
            local execve_id = logline:gets("observer.event.id")
            grouper1:feed(logline)
		end
	end
end

-- Функция сработки группера
function on_grouped(grouped)
	if not grouped or not grouped.aggregatedData or not grouped.aggregatedData.loglines then
        return
    end
    
    local events = grouped.aggregatedData.loglines
    local event_count = #events
    log(event_count)
    local first_event = events[1]
    local second_event = events[2]
    local last_event = events[3]

    local log_exec = ""
	local log_sys_openat = ""
    local log_sys_execve = ""

    for _, event in ipairs(events) do
        --local crontab_command = event:gets("initiator.command.executed")
        --local event_id = event:gets("observer.event.id")
        --log(crontab_command)
        --log(event_id)
        if event:gets("observer.event.type") == "SYSCALL" then
            if event:gets("target.syscall.name") == "openat" then
                log_sys_openat = event
            else
                log_sys_execve = event
            end
        else
            log_exec = event
        end
    end

    if grouped.aggregatedData.unique.total >= 3 then
		local log_exec = ""
		local log_sys_openat = ""
        local log_sys_execve = ""
        
		for _, log in ipairs(grouped.aggregatedData.loglines) do
			if log:gets("observer.event.type") == "SYSCALL" and log:gets("target.syscall.name") == "openat" then
				log_sys_openat = log
                local syscall_openat_id = log_sys_openat:gets("observer.event.id")
                --log(syscall_openat_id)
              
            end

            if log:gets("observer.event.type") == "SYSCALL" and log:gets("target.syscall.name") == "execve" then
				log_sys_execve = log
                local syscall_execve_id = log_sys_execve:gets("observer.event.id")
                --log(syscall_execve_id)
            end

            if log:gets("observer.event.type") == "EXECVE" or log:gets("observer.event.type") == "PROCTITLE" then
				log_exec = log
                local command = log_exec:gets("initiator.command.executed")
                local execve_id = log_exec:gets("observer.event.id")
                --log(log_exec)
            end
    	end
        log(syscall_openat_id)
        log(syscall_execve_id)
        log(execve_id)
        
-- Проверяем, что в группере находятся как события EXECVE/PROCTITLE, так и SYSCALL        
        if log_exec ~="" and log_sys_openat ~= "" and log_sys_execve ~= "" then
--            local command = log_exec:gets("initiator.command.executed")
--            local syscall_openat_id = log_sys_openat:gets("observer.event.id")
--            local syscall_execve_id = log_sys_execve:gets("observer.event.id")
--            local execve_id = log_exec:gets("observer.event.id")
            --log(command)    
            local logger = command .. "  <->  " .. syscall_openat_id .. " <-> " .. syscall_execve_id
            --log (logger)
--           local is_command = analyze(command)        
                
-- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name=log_sys:gets("initiator.user.name"),
                    header=header,
                    command=command,
                    command_path=log_sys:gets("initiator.process.path.full")
                    },
                risk_level = 8.0, 
                asset_ip = log_exec:get_asset_data("observer.host.ip"),
                asset_hostname = log_exec:get_asset_data("observer.host.hostname"),
                asset_fqdn = log_exec:get_asset_data("observer.host.fqdn"),
                asset_mac = log_exec:get_asset_data(""),
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                logs = grouped.aggregatedData.loglines,
                mitre = {"T1048.001"},
                trim_logs = 10
                }
            )
            grouper1:clear()
        end    
    end    
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)