-- Шаблон алерта
local template = [[
	Обнаружена попытка архивации файлов через скрипт.
	Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Путь к архиву: {{ .Meta.command_path }}
]]

-- Параметры группера
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"
local detection_window = "3m"

-- Массив с регулярными выражениями
local extension_patterns = {"%.bz2$", "%.gz$", "%.tar%.%w+$", "%.tar$", "%.zip$", "%.rar$", "%.7z$"}
local temporal_dirs = "(?:(\\/var)?\\/tmp|\\/home|\\/dev\\/shm|\\/etc|\\/var\\/log|\\/opt)\\/\\w+\\.(?:zip|(?:g|b)z2|7z|rar)"

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(path)
    local path = path:lower()
    local is_archive = "" 
    local is_temporal = ""

    is_temporal = path:search(temporal_dirs)

    if is_temporal then
       return true
    end

    for _, pattern in pairs(extension_patterns) do
        is_archive = path:match(pattern)

        if is_archive then
            return true
        end
    end

    return false
end

function on_logline(logline)
    if logline:gets("observer.event.type") == "PATH" then
		local target_path = logline:gets("target.object.path.full")
        local is_archive = analyze(target_path)
        if is_archive then
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
    local log_path = nil
	local log_sys = nil

    if unique_events > 1 then
		for _, log in ipairs(events) do
			if log:gets("observer.event.type") == "SYSCALL" and log:gets("target.syscall.name") == "openat" then
				log_sys = log
			else
				log_path = log
			end
		end
        
        if log_path and log_sys then
           local archive_path = log_path:gets("target.object.path.full")
           local interpreter_lib = log_sys:get("initiator.process.path.name")
           local initiator_name = log_sys:get("initiator.user.name") or "Пользователь неопределен"
                
-- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command=interpreter_lib,
                    command_path=archive_path
                    },
                risk_level = 7.5, 
                asset_ip = log_sys:get_asset_data("observer.host.ip"),
                asset_hostname = log_sys:get_asset_data("observer.host.hostname"),
                asset_fqdn = log_sys:get_asset_data("observer.host.fqdn"),
                asset_mac = log_sys:get_asset_data(""),
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                logs = events,
                mitre = {"T1020", "T1537", "T1560.002", "T1567"},
                trim_logs = 10
                }
            )
            grouper1:clear()
        end    
    end    
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)