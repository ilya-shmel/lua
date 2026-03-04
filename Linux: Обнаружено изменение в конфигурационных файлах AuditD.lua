-- Шаблон алерта
local template = [[
	Подозрение на редактирование файлов конфигурации auditd.
	Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Имя файла: {{ .Meta.file_path }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого команда выполнена: {{ .Meta.command_path }}
]]

local config_pattern = "^\\/etc\\/(lib)?audi(:?t|sp)(?:(\\/(?:audit\\.(?:rules|conf)))|\\/(?:rules\\.d|plugins\\.d)|\\/dispatcher\\.conf|\\.conf|\\/\\S+)$"

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze_string(string)
    local lower_string = string:lower()
    local is_regex = lower_string:search(config_pattern)
        if is_regex then
            return is_regex
        end
end

-- Функция обработки логлайна
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    
    if event_type == "SYSCALL" then
		local syscall_id = logline:gets("target.syscall.id")
               
        if syscall_id == "257" or syscall_id == "1" or syscall_id == "2" or syscall_id == "76" then
			grouper1:feed(logline)
        end
    elseif event_type == "PATH" then
        local file_path = logline:gets("target.object.path.full")
        local path_nametype = logline:gets("target.object.type"):lower()
        local is_path = analyze_string(file_path)
        
        if is_path and path_nametype == "normal" then
            grouper1:feed(logline)
        end
    end
    
end

-- Функция сработки группера
function on_grouped(grouped)
	local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total

    if unique_events > 1 then
		local log_path = nil
        local log_sys = nil
		for _, event in ipairs(events) do
			local event_type = event:gets("observer.event.type")
            if event_type == "SYSCALL" then
				log_sys = event
			else
				log_path = event
            end
		end
        
        if log_sys and log_path then
           local command_executed = log_sys:gets("initiator.process.path.name")
           local executed_path = log_sys:gets("initiator.process.path.full")
           local initiator_name = log_sys:gets("initiator.user.name")
           local file_name = log_path:gets("target.object.path.full")
           local host_ip = log_sys:get_asset_data("observer.host.ip")
           local host_name = log_sys:get_asset_data("observer.host.hostname")
           local host_fqdn = log_sys:get_asset_data("observer.host.fqdn") 
                
-- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command=command_executed,
                    command_path=executed_path,
                    file_path=file_name
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
                logs = events,
                mitre = {"T1562", "T1562.001", "T1047"},
                trim_logs = 15
                }
            )
            grouper1:clear()
        end    
    end    
end

-- Группер
grouper1 = grouper.new({"observer.host.ip", "observer.host.hostname", "observer.event.id"}, {"observer.event.type"}, "@timestamp,RFC3339", "1m", on_grouped)