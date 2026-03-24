local template = [[
Подозрение на атаку Golden Ticket.


ЦЕЛЕВОЙ УЗЕЛ:
{{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
{{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
Пользователь (инициатор): {{ .Meta.user_name }}
Тип шифрования: {{.Meta.encryption}}
Критичность - {{.Meta.vulnerability}}   
Процесс: {{.Meta.process_path}}
]]

local detection_window1 = "10m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "operation.type"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local prefix = "(?:^|\\s+|\"|\'|`|\\||&|\\\\|^.*)"
local suffix = "(?:$|\\s+|\"|\'|`|\\||&|\\\\|.*$)"
local golden_ticket_tools_regex = prefix.. "(?:(invoke-)?mimikatz(\\.exe)?|(?:kerberos|lsadump)::(?:golden|dcsync|lsa)|rubeus(?:\\.exe|\\s+golden)|power(?:sploit|view)|(?:ticketer|get(?:st|tg(?:t|s)))\\.py|(invoke-)?kerberoast|(?:blood|sharp)hound|impacket|sekurlsa|asreproast|goldenticket)" ..suffix
local dcsync_patterns_regex = prefix.. "(?:lsadump|\\/user|privilege|sekurlsa|crypto):{1,2}(?:dcsync|krbtgt|debug|msv|logonpasswords|tickets|capi|cng|sam|secrets|backupkeys|dpapi)" ..suffix
local krbtgt_patterns_regex = prefix.. "(?:kerberos::(?:list|tgt|purge|ptc)|\\/(?:rc4|aes(?:128|256)):\\w{32,64}|\\/(?:de|group|sid)s:|\\/(?:ex|im)port|/ticket|\\s+golden|\\s+krbtgt|\\/startoffset|\\/endin|\\/ptt|\\/id|\\/user:[\\w\\.\\-$]+|\\/domain:[\\w\\.\\-]+|\\/sid:S-1-5-21-[-,\\d]+|\\/krbtgt:\\w{32,})" ..suffix
local powershell_kerberos_patterns_regex = prefix.. "(?:get(-)?(?:authorizationgroups|current.*principal|(net)?domain(?:spnticket|user)|userhunter)|invoke-(?:kerberoast|userhunter)|(?:\\[|assemblyname\\s+)system\\.identitymodel(\\.tokens\\.kerberosrequestorsecuritytoken)?|add\\-type.*identitymodel|new\\-object.*kerberos)" ..suffix

local suspicious_event_codes = {"4768", "4769", "4624", "4634", "4672", "4673", "4648"}

-- Функция вызова алерта
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

-- Стандартная функция анализа строк на предмет прохождения регулярного выражения
local function analyze(cmd)
    cmd = cmd:lower()
    return cmd:search(golden_ticket_tools_regex) or cmd:search(dcsync_patterns_regex) or cmd:search(krbtgt_patterns_regex) or cmd:search(powershell_kerberos_patterns_regex)
end

-- Вспомогательная функция бинарного поиска последнего времени <= target
local function find_last_less_equal(timestamps, target)
    local low_range, high_range = 1, #timestamps
    while low_range <= high_range do
        local middle_index = math.floor((low_range + high_range) / 2)
        if timestamps[middle_index] <= target then
            low_range = middle_index + 1
        else
            high_range = middle_index - 1
        end
    end
    return high_range  -- индекс последнего подходящего, или 0, если его нет
end
    
-- Вспомогательные функции
local function add_finding(analysis, indicator, details, hint, is_suspisious)
    table.insert(analysis.indicators, indicator)
        
    if hint then table.insert(analysis.correlation_hints, hint) end
    
    if is_suspisious then analysis.is_suspicious = true end
end
    
local function has_rc4(encryption)
    encryption = encryption:lower()
    return encryption and encryption:match("^.*rc4.*$")
end
    
local function is_critical_service(service_name)
    local critical_services = {
        "CIFS", "HOST", "LDAP", "KRBTGT", "MSSQL", "HTTP"
    }
    for _, service in ipairs(critical_services) do
        if service_name:match("^.*" .. service .. ".*$") then
            return true
        end
    end
    return false
end

--Функция корреляции событий TGT и TGS 
local function correlate_tgt_tgs_events(events)
    local tgt_events = {}      -- храним только нужные поля
    local tgs_events = {}
    local correlations = {}

-- Проход по событиям: сбор данных
    for _, event in ipairs(events) do
        local event_id = event:gets("observer.event.id")
        local timestamp = event:gets("@timestamp")
        local user_name = event:get("target.user.name") or event:get("initiator.user.name")
        local outcome_description = event:gets("outcome.description")
        local service_name = event:gets("target.auth.service.name")

        if event_id == "4768" then
            table.insert(tgt_events, {
                user = user_name,
                timestamp = timestamp
            })
        elseif event_id == "4769" then
            table.insert(tgs_events, {
                event = event,
                user = user_name,
                timestamp = timestamp,
                outcome = outcome_description,
                service = service_name
            })
        end
-- событие 4624 пока игнорируем
    end

-- Группируем времена TGT по пользователям и сортируем
    local user_tgts = {}
    
    for _, tgt in ipairs(tgt_events) do
        local current_user = tgt.user
        
        if #user_tgts[current_user] == 0 or user_tgts[current_user] == false then
            user_tgts[current_user] = {}
        end

        table.insert(user_tgts[current_user], tgt.timestamp)
    end
    
    for _, timestamps in pairs(user_tgts) do
        table.sort(timestamps)
    end

-- Проверка каждого TGS
    for _, tgs in ipairs(tgs_events) do
        local current_user = tgs.user
        local timestamps = user_tgts[current_user]
        local has_preceding_tgt = timestamps and find_last_less_equal(timestamps, tgs.timestamp) > 0

        if not has_preceding_tgt and tgs.outcome == "0x0" then
            table.insert(correlations, {
                type = "TGS_WITHOUT_TGT",
                event = tgs.event,
                user = tgs.user,
                service = tgs.service,
                description = "TGS запрос без предшествующего TGT для пользователя " ..tgs.user
            })
        end
    end

    return correlations
end

local function analyze_kerberos_events(event)
    local analysis = {
        is_suspicious = false,
        indicators = {},
        attack_type = "",
        correlation_hints = {}
    }
    
    -- Получаем все поля одной группой
    local fields = {
        event_id = event:gets("observer.event.id"),
        outcome = event:gets("outcome.description"),
        target_user = event:get("target.user.name"),
        initiator_encryption = event:gets("initiator.auth.encryption.name"),
        target_encryption = event:gets("target.auth.encryption.name"),
        service_name = event:gets("target.auth.service.name"),
        initiator_ip = event:gets("initiator.host.ip"),
        ticket_lifetime = event:gets("target.auth.ticket.lifetime"),
        preauth_type = event:gets("initiator.auth.preauth.type"),
        logon_type = event:gets("logon.type")
    }
    
-- Анализ по типу события
    if fields.event_id == "4768" then
        -- RC4 шифрование
        if has_rc4(fields.initiator_encryption) or has_rc4(fields.target_encryption) then
            add_finding(analysis, "TGT запрос с RC4 шифрованием (downgrade attack)", 
                "Event ID 4768: RC4 encryption detected", "RC4_TGT_REQUEST", true)
        end
        
-- Большой TTL
        if fields.ticket_lifetime then
            local hours = tonumber(fields.ticket_lifetime) / 3600
            if hours > 10 then
                add_finding(analysis, string.format("Билет с подозрительно долгим временем жизни: %.1f часов", hours),
                    "Abnormal ticket lifetime detected", "LONG_LIFETIME_TICKET", true)
            end
        end
        
-- Отсутствие пре-аутентификации
        if fields.preauth_type == "0" or fields.preauth_type == "" then
            add_finding(analysis, "TGT запрос без пре-аутентификации",
                "No pre-authentication required", "NO_PREAUTH", true)
        end
        
-- Успешный TGT
        if fields.outcome == "0x0" then
            add_finding(analysis, nil, "Successful TGT request", "SUCCESS_TGT", false)
        end
        
    elseif fields.event_id == "4769" then
-- RC4 с успешным исходом
        if fields.outcome == "0x0" and (has_rc4(fields.initiator_encryption) or has_rc4(fields.target_encryption)) then
            add_finding(analysis, "Успешный TGS запрос с RC4 шифрованием",
                "Successful TGS with RC4 encryption", "RC4_TGS_SUCCESS", true)
        end
        
-- Доступ к критическим сервисам
        if fields.service_name and is_critical_service(fields.service_name) then
            add_finding(analysis, "TGS запрос к критическому сервису: " .. fields.service_name,
                "Access to critical service", "CRITICAL_SERVICE_ACCESS", true)
        end
        
    elseif fields.event_id == "4672" and fields.target_user then
        add_finding(analysis, "Назначение специальных привилегий пользователю: " .. fields.target_user,
            "Special privileges assigned", "SPECIAL_PRIVILEGES", true)
        analysis.attack_type = "Privilege Escalation via Golden Ticket"
        
    elseif fields.event_id == "4624" then
        if fields.logon_type == "3" or fields.logon_type == "9" then
            add_finding(analysis, "Сетевой логон или новые учетные данные",
                "Network logon or new credentials", "NETWORK_LOGON", false)
        end
    end
    
-- Корректировки 
    if fields.initiator_ip == "::1" or fields.initiator_ip == "127.0.0.1" then
        add_finding(analysis, "Локальная аутентификация к контроллеру домена",
            nil, "LOCAL_DC_AUTH", false)
    end
    
    return analysis
end

-- Функция обработки логлайна 
function on_logline(logline)
    local event_category = logline:gets("event.category")
    local event_id = logline:gets("observer.event.id")
    local command_executed = logline:gets("initiator.command.executed")
    local process_path = logline:gets("initiator.process.path.full") or logline:gets("initiator.process.path.name")
    local outcome_description = logline:gets("outcome.description")
    local encryption_name = (logline:gets("initiator.auth.encryption.name") .. logline:gets("target.auth.encryption.name")):lower()
    
    if contains(suspicious_event_codes, event_id) then
       set_field_value(logline, "operation.type", "event")
       grouper1:feed(logline)
    end

    local is_attack = analyze(command_executed)
    
    if is_attack then
        set_field_value(logline, "operation.type", "command")
        grouper2:feed(logline)
    end
end

-- Функция работы группера
function on_grouped1(grouped)
    local events = grouped.aggregatedData.loglines
    local suspicious_tgs = 0
    local suspicios_kerberos = 0

    if events > 1 then
        local user_name = events[1]:get("initiator.user.name") or events[1]:get("target.user.name") or "Не определено"
        local host_ip = events[1]:get("observer.host.ip", "Не определено")
        local host_name = events[1]:get("observer.host.hostname", "Не определено")
        local host_fqdn = events[1]:get("observer.host.fqdn", "Не определено")  
        
        if event[1]:gets("operation.type") == "command" and #events > 1 then
            local command_executed = events[1]:get("initiator.command.executed")
            local process_path = events[1]:get("initiator.process.path.full") or events[1]:get("initiator.process.path.name")
            
            alert_function(command_executed, user_name, process_path, host_ip, host_name, host_fqdn, events)
            grouper1:clear()            
        elseif event[1]:gets("operation.type") == "event" and #events > 1 then
            local correlations = correlate_tgt_tgs_events(events)

            for _, correlation in ipairs(correlations) do
                if correlation.type == "TGS_WITHOUT_TGT" then
                    suspicios_tgs = suspicios_tgs + 1
                end
            end
        
            local analyze = analyze_kerberos_events(events)

            for _, correlation in analyze do
                if correlation.is_suspicious then
                    suspicios_kerberos = suspicios_kerberos + 1
                end
            end    

            if suspicios_tgs > 2 or suspicios_kerberos > 2 then
                local user_name = events[1]:get("initiator.user.name") or events[1]:get("target.user.name") or "Не определено"
                local host_ip = events[1]:get("observer.host.ip", "Не определено")
                local host_name = events[1]:get("observer.host.hostname", "Не определено")
                local host_fqdn = events[1]:get("observer.host.fqdn", "Не определено")

                alert_function("", user_name, "", host_ip, host_name, host_fqdn, events)
                grouper1:clear()
            end
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)