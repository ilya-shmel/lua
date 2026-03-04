-- Шаблон алерта
local template = [[
	Обнаружена остановка межсетевого экрана.
	Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Имя программы: {{ .Meta.command }}
    Путь инициатора: {{ .Meta.command_path }}
]]

-- Параметры группера
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"target.service.name"}
local grouped_time_field = "@timestamp,RFC3339"
local detection_window = "1m"

-- Массив с регулярными выражениями
local services_names = {"firewalld", "ufw", "iptables", "nftables", "netfilter", "fail2ban", "ip6tables", "ebtables"}

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(service)
    local service = service:lower()
    local is_firewall = nil

    for _, pattern in ipairs(services_names) do
        is_firewall = service:match(pattern)
    
        if is_firewall then
            return true
        end
    end
    return false
end

function on_logline(logline)
    service_name = logline:gets("target.service.name")
		local is_firewall = analyze(service_name)

        if is_firewall then
			grouper1:feed(logline)
	    end
end

-- Функция сработки группера
function on_grouped(grouped)
	local events = grouped.aggregatedData.loglines


    if #events > 0 then
           local initiator_path = events[1]:gets("initiator.process.path.full")
           local firewall_name = events[1]:get("target.service.name")
           local initiator_name = events[1]:get("initiator.user.name") or "Пользователь неопределен"
                
-- Функция алерта
            alert({
                template = template,
                meta = {
                    user_name=initiator_name,
                    command=firewall_name,
                    command_path=initiator_path
                    },
                risk_level = 7.5, 
                asset_ip = events[1]:get_asset_data("observer.host.ip"),
                asset_hostname = events[1]:get_asset_data("observer.host.hostname"),
                asset_fqdn = events[1]:get_asset_data("observer.host.fqdn"),
                asset_mac = events[1]:get_asset_data(""),
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                logs = events,
                mitre = {"T1562"},
                trim_logs = 10
                }
            )
            grouper1:clear()
    end    
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)