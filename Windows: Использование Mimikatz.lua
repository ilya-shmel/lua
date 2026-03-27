local threat_titles = {
    PRIVILEGE = "Обнаружена манипуляция привилегиями токена текущего процесса",
    SEKURLSA = "Обнаружен дамп учётных данных из памяти LSASS",
    KERBEROS = "Обнаружено использование модуля работы с Kerberos-тикетами",
    LSADUMP = "Обнаружено извлечение данных из SAM или LSA",
    TOKEN = "Обнаружена манипуляция токенами процессов",
    CRYPTO = "Обнаружено использование модуля работы с CryptoAPI и сертификатами",
    DPAPI = "Обнаружено использование модуля расшифровки данных, защищённых Windows DPAPI",
    SEKURLSA = "Обнаружен доступ к Windows Credential Vault"
}

local template = [[
{{.Meta.alert_title}}

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{.Meta.observer_ip}}
Хост: {{.Meta.observer_hostname}}
FQDN: {{.Meta.observer_fqdn}}

ИНИЦИАТОР:
Пользователь: {{.Meta.user_name}}
Домен: {{.Meta.user_domain}}
UID: {{.Meta.user_id}}

ВЫПОЛНЕННЫЕ КОМАНДЫ:
{{- range $key, $triple := .Meta.triple_list }}
Родительский процесс: {{ $triple.parent }}
Путь процесса: {{ $triple.path }}
Команда: {{ $triple.command }}

{{ end -}}
]]

local detection_window = "1m"
local grouped_by = {
    "observer.host.ip",
    "observer.host.hostname",
    "initiator.user.name"
}
local aggregated_by = {
    "target.process.path.full",
    "initiator.process.parent.path.original",
    "initiator.command.executed",
    "observer.event.type"
}
local grouped_time_field = "@timestamp,RFC3339"

-- паттерны Mimikatz, по аналогии с multiplexer_patterns
local mimikatz_patterns = {
    PRIVILEGE = {
        pattern = "(?i)(?:^|\\s+|\"|\'|\\\\|\\/)(?:privilege::)",
        risk = 6.5,
        mitre = {"T1134"}
    },
    SEKURLSA = {
        pattern = "(?i)(?:^|\\s+|\"|\'|\\\\|\\/)(?:sekurlsa::)",
        risk = 6.5,
        mitre = {"T1003.001", "T1550.002", "T1550.003"}
    },
    KERBEROS = {
        pattern = "(?i)(?:^|\\s+|\"|\'|\\\\|\\/)(?:kerberos::)",
        risk = 6.5,
        mitre = {"T1558.001", "T1558.002", "T1550.003"}
    },
    LSADUMP = {
        pattern = "(?i)(?:^|\\s+|\"|\'|\\\\|\\/)(?:lsadump::)",
        risk = 6.5,
        mitre = {"T1003.002", "T1003.004", "T1003.006", "T1207", "T1098"}
    },
    TOKEN = {
        pattern = "(?i)(?:^|\\s+|\"|\'|\\\\|\\/)(?:token::)",
        risk = 6.5,
        mitre = {"T1134", "T1134.005"}
    },
    CRYPTO = {
        pattern = "(?i)(?:^|\\s+|\"|\'|\\\\|\\/)(?:crypto::)",
        risk = 6.5,
        mitre = {"T1649", "T1552.004"}
    },
    DPAPI = {
        pattern = "(?i)(?:^|\\s+|\"|\'|\\\\|\\/)(?:dpapi::)",
        risk = 6.5,
        mitre = {"T1555", "T1555.003", "T1555.004"}
    },
    VAULT = {
        pattern = "(?i)(?:^|\\s+|\"|\'|\\\\|\\/)(?:vault::)",
        risk = 6.5,
        mitre = {"T1555", "T1555.004"}
    }
}

local function analyze_mimikatz(cmd)
    local found = {}
    for tech, data in pairs(mimikatz_patterns) do
        if cmd:search(data.pattern) then
            table.insert(found, {
                tech = tech,
                risk = data.risk,
                mitre = data.mitre
            })
        end
    end
    return found
end

function on_logline(logline)

    local command = logline:gets("initiator.command.executed")
    if command then
        local matches = analyze_mimikatz(command)
        if #matches > 0 then
            grouper1:feed(logline)
        end
    end
end

function on_grouped(grouped)
    if grouped.aggregatedData.aggregated.total >= 1 then
        local logline = grouped.aggregatedData.loglines[1]

        local triple_list = {}
        local seen = {}
        local detected_techs = {}
        local alert_titles_list = {}
        local risk_level = 0

        for _, logline in ipairs(grouped.aggregatedData.loglines) do
            local command = logline:gets("initiator.command.executed", "")
            local matches = analyze_mimikatz(command)

            for _, match in ipairs(matches) do
                local tech = match.tech

                if not detected_techs[tech] then
                    detected_techs[tech] = true

                    local title = threat_titles[tech]
                    if title then
                        table.insert(alert_titles_list, title)
                    end

                    risk_level = math.max(risk_level, match.risk)
                end
            end

            local parent = logline:gets("initiator.process.parent.path.original", "Не определено")
            local path = logline:gets("target.process.path.full", "Не определено")
            local key = parent .. "|" .. path .. "|" .. command

            if not seen[key] then
                seen[key] = true
                table.insert(triple_list, {
                    parent = parent,
                    path = path,
                    command = command
                })
            end
        end
        local alert_title = "Обнаружено использование Mimikatz:\n- " ..
            table.concat(alert_titles_list, "\n- ")
    
        local first = grouped.aggregatedData.loglines[1]
        local meta = {
            alert_title = alert_title,
            observer_ip = first:gets("observer.host.ip", "Не определено"),
            observer_hostname = first:gets("observer.host.hostname", "Не определено"),
            observer_fqdn = first:gets("observer.host.fqdn", "Не определено"),
            user_name = first:gets("initiator.user.name", "Не определено"),
            user_domain = first:gets("initiator.user.domain", "Не определено"),
            user_id = first:gets("initiator.user.id", "Не определено"),
            triple_list = triple_list
        }

        alert({
            template = template,
            meta = meta,
            risk_level = risk_level,
            asset_ip = first:get_asset_data("observer.host.ip"),
            asset_hostname = first:get_asset_data("observer.host.hostname"),
            asset_fqdn = first:get_asset_data("observer.host.fqdn"),
            asset_mac = "",
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "",
            logs = grouped.aggregatedData.loglines,
            trim_logs = 10
        })

        grouper1:clear()
    end
end

grouper1 = grouper.new(
    grouped_by,
    aggregated_by,
    grouped_time_field,
    detection_window,
    on_grouped
)