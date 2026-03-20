-- Табличные списки
service_account_whitelist = storage.new("service_accounts|Windows: Был запрошен сервисный тикет Kerberos")
enterprise_whitelist = storage.new("enterprise_whitelist|Windows: Был запрошен сервисный тикет Kerberos")
suspicious_services_blacklist = storage.new("suspicious_services|Windows: Был запрошен сервисный тикет Kerberos")


-- Шаблоны алерта
local template = [[
	Подозрение на запрос сервисного тикета Kerberos.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь (инициатор): {{ .Meta.user_name }}
    Тип шифрования: {{.Meta.encryption}}
    Критичность - {{.Meta.vulnerability}}   
]]

local critical_encryption_types = {
    ["0x1"] = {
        risk = 25,
        name = "DES",
        description = "КРИТИЧЕСКАЯ УГРОЗА: DES шифрование",
        critical = true
    },
    ["1"] = {
        risk = 25,
        name = "DES",
        description = "КРИТИЧЕСКАЯ УГРОЗА: DES шифрование",
        critical = true
    },
    ["0x17"] = {
        risk = 15,
        name = "RC4",
        description = "ВЫСОКИЙ РИСК: RC4 Kerberoasting",
        critical = true
    },
    ["23"] = {
        risk = 15,
        name = "RC4",
        description = "ВЫСОКИЙ РИСК: RC4 Kerberoasting",
        critical = true
    },
    ["0x11"] = {
        risk = 0,
        name = "AES128",
        description = "Безопасное AES128",
        critical = false
    },
    ["17"] = {
        risk = 0,
        name = "AES128",
        description = "Безопасное AES128",
        critical = false
    },
    ["0x12"] = {
        risk = 0,
        name = "AES256",
        description = "Наиболее безопасное AES256",
        critical = false
    },
    ["18"] = {
        risk = 0,
        name = "AES256",
        description = "Наиболее безопасное AES256",
        critical = false
    }
}

-- Переменные для группера
local detection_window = "8m"
local grouped_by = {"observer.host.hostname", "initiator.host.ip"}
local aggregated_by = {"target.user.name", "target.service.name", "initiator.auth.encryption.original"}
local grouped_time_field = "@timestamp,RFC3339"

-- Функция проверки активности легальных сервисов
local function is_enterprise_activity(user_name, service_name, client_ip)
    if user_name:find("%$$") and (user_name:find("exch") or user_name:find("mbx")) then
        return true
    end
    
    if user_name:find("%$$") and (service_name:find("dc") or service_name:find("controller")) then
        return true
    end
    return false
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    
    if event_type == "audit_success" then 
        local user_name = logline:gets("target.user.name"):lower()
        local service_name = logline:gets("target.service.name"):lower()
        local client_ip = logline:gets("initiator.host.ip"):lower()
        local encryption_type = logline:gets("initiator.auth.encryption.original")

                        
        local is_service_account = service_account_whitelist:get(user_name, "account")
        local is_legal_service = enterprise_whitelist:get(service_name, "service")
        local is_legal_service_account = enterprise_whitelist:get(user_name, "account")
        local is_suspicious_service = suspicious_services_blacklist:get(service_name, "service")

        if is_service_account or is_legal_service or is_legal_service_account then
            return
        end
        
        local current_encryption_type = critical_encryption_types[encryption_type]

        if current_encryption_type.critical or is_suspicious_service then
            grouper1:feed(logline)
        end

        local is_enterprise = is_enterprise_activity(user_name, service_name, client_ip)
        
        if (current_encryption_type.name == "AES128" or current_encryption_type.name == "AES256") and is_enterprise == false then
            grouper1:feed(logline)
        end


    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines

    if #events > 3 then
       local target_name = events[1]:get("target.user.name") or "Пользователь не определен" 
       local host_ip = events[1]:get_asset_data("observer.host.ip")
       local host_name = events[1]:get_asset_data("observer.host.hostname")
       local host_fqdn = events[1]:get_asset_data("observer.host.fqdn")
       local encryption_type = events[1]:gets("initiator.auth.encryption.original")
       local encryption_caption = critical_encryption_types[encryption_type]
       local encryption_type = encryption_type .. " (" .. encryption_caption.name .. ")"
       local vulnerability_caption = encryption_caption.description
       local service_name = events[1]:get("target.service.name") or "Служба не определена"
       
       alert({
            template = template,
            meta = {
                user_name=target_name,
                encryption=encryption_type,
                vulnerability=vulnerability_caption
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
            logs = events,
            mitre = {"T1558.002"},
            trim_logs = 10
            }
        )
       
       grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)