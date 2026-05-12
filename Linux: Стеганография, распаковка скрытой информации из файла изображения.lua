local template = [[
Обнаружено использование инструментов стеганографии для извлечения скрытой информации.


ЦЕЛЕВОЙ УЗЕЛ:
IP: {{.Meta.observer_ip}}
Хост: {{.Meta.observer_hostname}}
FQDN: {{.Meta.observer_fqdn}}


ИНИЦИАТОР:
Пользователь: {{.Meta.user_name}}
UID: {{.Meta.user_id}}
Процесс: {{.Meta.command_path}}


ВЫПОЛНЕННАЯ КОМАНДА:
{{.Meta.command}}


ТИП ОПЕРАЦИИ:
{{.Meta.operation_type}}
]]

local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

local steganography_tools = {
    STEGHIDE_EXTRACT = {
        pattern = "(?i)steghide\\s+(?:extract|info)",
        risk = 8.0,
        mitre = {"T1001.002", "T1027.003", "T1140"}
    },
    OUTGUESS_EXTRACT = {
        pattern = "(?i)outguess\\s+(?:-r|-e)",
        risk = 8.0,
        mitre = {"T1001.002", "T1027.003", "T1140"}
    },
    ZSTEG_EXTRACT = {
        pattern = "(?i)zsteg",
        risk = 7.5,
        mitre = {"T1001.002", "T1027.003"}
    },
    STEGCRACKER = {
        pattern = "(?i)stegcracker",
        risk = 8.5,
        mitre = {"T1001.002", "T1027.003", "T1110"}
    },
    STEGSEEK = {
        pattern = "(?i)stegseek",
        risk = 8.5,
        mitre = {"T1001.002", "T1027.003"}
    },
    EXIFTOOL_SUSPICIOUS = {
        pattern = "(?i)exiftool\\s+.*\\.(?:jpg|jpeg|png|bmp|gif|tiff|webp)",
        risk = 6.0,
        mitre = {"T1001.002", "T1083"}
    },
    BINWALK_EXTRACT = {
        pattern = "(?i)binwalk\\s+(?:-e|--extract).*\\.(?:jpg|jpeg|png|bmp|gif)",
        risk = 7.5,
        mitre = {"T1001.002", "T1140"}
    },
    FOREMOST_EXTRACT = {
        pattern = "(?i)foremost\\s+.*\\.(?:jpg|jpeg|png|bmp|gif)",
        risk = 7.5,
        mitre = {"T1001.002", "T1140"}
    },
    UNZIP_FROM_IMAGE = {
        pattern = "(?i)unzip\\s+.*\\.(?:jpg|jpeg|png|bmp|gif)",
        risk = 7.0,
        mitre = {"T1001.002", "T1140"}
    },
    STRINGS_IMAGE = {
        pattern = "(?i)strings\\s+.*\\.(?:jpg|jpeg|png|bmp|gif)",
        risk = 6.5,
        mitre = {"T1001.002", "T1083"}
    },
    STEGDETECT = {
        pattern = "(?i)stegdetect",
        risk = 7.0,
        mitre = {"T1001.002", "T1083"}
    },
    STEGBREAK = {
        pattern = "(?i)stegbreak",
        risk = 8.0,
        mitre = {"T1001.002", "T1110"}
    },
    OPENSTEGO = {
        pattern = "(?i)openstego",
        risk = 7.5,
        mitre = {"T1001.002", "T1027.003"}
    },
    SNOW = {
        pattern = "(?i)snow\\s+(?:-C|-S)",
        risk = 7.5,
        mitre = {"T1001.002", "T1027.003"}
    },
    F5 = {
        pattern = "(?i)f5\\s+(?:-x|-extract)",
        risk = 7.5,
        mitre = {"T1001.002", "T1027.003"}
    },
    JPHIDE = {
        pattern = "(?i)jphide\\s+(?:-x)",
        risk = 7.5,
        mitre = {"T1001.002", "T1027.003"}
    },
    JPSEEK = {
        pattern = "(?i)jpseek",
        risk = 7.5,
        mitre = {"T1001.002", "T1083"}
    },
    LSB_TOOLS = {
        pattern = "(?i)(?:lsb-toolkit|stegpy|stepic)",
        risk = 7.5,
        mitre = {"T1001.002", "T1027.003"}
    },
    DEEPSOUND = {
        pattern = "(?i)deepsound",
        risk = 7.5,
        mitre = {"T1001.002", "T1027.003"}
    },
    SPECTROLOGY = {
        pattern = "(?i)sonic-visualiser|audacity.*spectrogram",
        risk = 7.0,
        mitre = {"T1001.002", "T1083"}
    },
    FIND_IMAGES = {
        pattern = "(?i)find\\s+.*\\s+(?:-name|--name)\\s+.*\\.(?:jpg|jpeg|png|bmp|gif)",
        risk = 6.0,
        mitre = {"T1083", "T1005"}
    },
    COPY_IMAGES = {
        pattern = "(?i)(?:cp|mv|scp|rsync)\\s+.*\\.(?:jpg|jpeg|png|bmp|gif)\\s+(?:/tmp|/var/tmp|/dev/shm)",
        risk = 6.5,
        mitre = {"T1074.001"}
    },
    PASSWORD_EXTRACT = {
        pattern = "(?i)(?:steghide|outguess|stegcracker)\\s+.*(?:-p\\s+|-passphrase\\s+|--password\\s+)",
        risk = 8.5,
        mitre = {"T1001.002", "T1110"}
    }
}

local operation_types = {
    STEGHIDE_EXTRACT = "Извлечение данных через steghide",
    OUTGUESS_EXTRACT = "Извлечение данных через outguess",
    ZSTEG_EXTRACT = "Анализ LSB стеганографии (zsteg)",
    STEGCRACKER = "Брутфорс пароля стеганографии (stegcracker)",
    STEGSEEK = "Быстрое извлечение стеганографии (stegseek)",
    EXIFTOOL_SUSPICIOUS = "Анализ метаданных изображения (exiftool)",
    BINWALK_EXTRACT = "Извлечение встроенных файлов (binwalk)",
    FOREMOST_EXTRACT = "Восстановление файлов из изображения (foremost)",
    UNZIP_FROM_IMAGE = "Распаковка архива из изображения",
    STRINGS_IMAGE = "Поиск строк в изображении",
    STEGDETECT = "Детектирование стеганографии",
    STEGBREAK = "Взлом стеганографии",
    OPENSTEGO = "Использование OpenStego",
    SNOW = "Извлечение whitespace-стеганографии (SNOW)",
    F5 = "Извлечение F5 стеганографии",
    JPHIDE = "Извлечение JPHide стеганографии",
    JPSEEK = "Поиск JPHide стеганографии",
    LSB_TOOLS = "LSB стеганография (lsb-toolkit/stegpy)",
    DEEPSOUND = "Аудио-стеганография (DeepSound)",
    SPECTROLOGY = "Спектрограмма аудио-стеганографии",
    FIND_IMAGES = "Поиск изображений для обработки",
    COPY_IMAGES = "Копирование изображений",
    PASSWORD_EXTRACT = "Извлечение с паролем"
}

local false_positive_patterns = {"(?i)--help|--version|-h|-v", "(?i)man\\s+(?:steghide|outguess|exiftool|binwalk)",
                                 "(?i)apt-get|dpkg|yum|dnf", "(?i)test|example|sample|demo"}

local function is_false_positive(cmd)
    for _, pattern in ipairs(false_positive_patterns) do
        if cmd:search(pattern) then
            return true
        end
    end
    return false
end

local function analyze_threat(cmd)
    if is_false_positive(cmd) then
        return nil, 0, nil
    end

    for threat_type, threat_data in pairs(steganography_tools) do
        if cmd:search(threat_data.pattern) then
            return threat_type, threat_data.risk, operation_types[threat_type], threat_data.mitre
        end
    end

    return nil, 0, nil, nil
end

function on_logline(logline)
    local event_type = logline:gets("observer.event.type")

    if event_type == "EXECVE" or event_type == "PROCTITLE" then
        local command = logline:gets("initiator.command.executed")
        if command and command ~= "" then
            local threat_type, _, _, _ = analyze_threat(command)
            if threat_type then
                grouper1:feed(logline)
            end
        end
    elseif event_type == "SYSCALL" then
        grouper1:feed(logline)
    end
end

function on_grouped(grouped)
    if grouped.aggregatedData.unique.total < 2 then
        return
    end

    local log_exec = nil
    local log_sys = nil

    for _, event in ipairs(grouped.aggregatedData.loglines) do
        local ev_type = event:gets("observer.event.type")
        if ev_type == "SYSCALL" then
            log_sys = event
        elseif ev_type == "EXECVE" or ev_type == "PROCTITLE" then
            log_exec = event
        end
    end

    if not log_exec or not log_sys then
        return
    end

    local command = log_exec:gets("initiator.command.executed")
    if not command or command == "" then
        return
    end

    local threat_type, risk, operation_type, mitre = analyze_threat(command)
    if not threat_type then
        return
    end

    alert({
        template = template,
        meta = {
            observer_ip = log_exec:gets("observer.host.ip") or "unknown",
            observer_hostname = log_exec:gets("observer.host.hostname") or "unknown",
            observer_fqdn = log_exec:gets("observer.host.fqdn") or "unknown",
            user_name = log_sys:gets("initiator.user.name") or "unknown",
            user_id = log_sys:gets("initiator.user.id") or "0",
            command_path = log_sys:gets("initiator.process.path.full") or "unknown",
            command = command,
            operation_type = operation_type
        },
        risk_level = risk,
        asset_ip = log_exec:get_asset_data("observer.host.ip"),
        asset_hostname = log_exec:get_asset_data("observer.host.hostname"),
        asset_fqdn = log_exec:get_asset_data("observer.host.fqdn"),
        asset_mac = "",
        create_incident = true,
        incident_group = "Data Exfiltration",
        assign_to_customer = false,
        incident_identifier = "",
        logs = grouped.aggregatedData.loglines,
        mitre = mitre or {"T1001.002"},
        trim_logs = 10
    })

    grouper1:clear()
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)