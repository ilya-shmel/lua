local template = [[
Подозрение на использование инструментов стеганографии для извлечения скрытой информации.

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
        pattern = "steghide\\s+(?:extract|info)",
        risk = 8.0,
        mitre = {"T1001.002", "T1027.003", "T1140"}
    },
    OUTGUESS_EXTRACT = {
        pattern = "outguess\\s+(?:-r|-e)",
        risk = 8.0,
        mitre = {"T1001.002", "T1027.003", "T1140"}
    },
    ZSTEG_EXTRACT = {
        pattern = "zsteg",
        risk = 7.5,
        mitre = {"T1001.002", "T1027.003"}
    },
    STEGCRACKER = {
        pattern = "stegcracker",
        risk = 8.5,
        mitre = {"T1001.002", "T1027.003", "T1110"}
    },
    STEGSEEK = {
        pattern = "stegseek",
        risk = 8.5,
        mitre = {"T1001.002", "T1027.003"}
    },
    EXIFTOOL_SUSPICIOUS = {
        pattern = "exiftool\\s+.*\\.(?:jpe?g|png|bmp|gif|tiff|webp)",
        risk = 6.0,
        mitre = {"T1001.002", "T1083"}
    },
    BINWALK_EXTRACT = {
        pattern = "binwalk\\s+(?:-e|--extract).*\\.(?:jpe?g|png|bmp|gif)",
        risk = 7.5,
        mitre = {"T1001.002", "T1140"}
    },
    FOREMOST_EXTRACT = {
        pattern = "foremost\\s+.*\\.(?:jpe?g|png|bmp|gif)",
        risk = 7.5,
        mitre = {"T1001.002", "T1140"}
    },
    UNZIP_FROM_IMAGE = {
        pattern = "unzip\\s+.*\\.(?:jpe?g|png|bmp|gif)",
        risk = 7.0,
        mitre = {"T1001.002", "T1140"}
    },
    STRINGS_IMAGE = {
        pattern = "strings\\s+.*\\.(?:jpe?g|png|bmp|gif)",
        risk = 6.5,
        mitre = {"T1001.002", "T1083"}
    },
    STEGDETECT = {
        pattern = "stegdetect",
        risk = 7.0,
        mitre = {"T1001.002", "T1083"}
    },
    STEGBREAK = {
        pattern = "stegbreak",
        risk = 8.0,
        mitre = {"T1001.002", "T1110"}
    },
    OPENSTEGO = {
        pattern = "openstego",
        risk = 7.5,
        mitre = {"T1001.002", "T1027.003"}
    },
    SNOW = {
        pattern = "snow\\s+(?:-c|-s)",
        risk = 7.5,
        mitre = {"T1001.002", "T1027.003"}
    },
    F5 = {
        pattern = "f5\\s+(?:-x|-extract)",
        risk = 7.5,
        mitre = {"T1001.002", "T1027.003"}
    },
    JPHIDE = {
        pattern = "jphide\\s+(?:-x)",
        risk = 7.5,
        mitre = {"T1001.002", "T1027.003"}
    },
    JPSEEK = {
        pattern = "jpseek",
        risk = 7.5,
        mitre = {"T1001.002", "T1083"}
    },
    LSB_TOOLS = {
        pattern = "(?:lsb-toolkit|stegpy|stepic)",
        risk = 7.5,
        mitre = {"T1001.002", "T1027.003"}
    },
    DEEPSOUND = {
        pattern = "deepsound",
        risk = 7.5,
        mitre = {"T1001.002", "T1027.003"}
    },
    SPECTROLOGY = {
        pattern = "sonic-visualiser|audacity[\\s\\S]*spectrogram",
        risk = 7.0,
        mitre = {"T1001.002", "T1083"}
    },
    FIND_IMAGES = {
        pattern = "find\\s+[\\s\\S]*\\s+(?:-name|--name)\\s+[\\s\\S]*\\.(?:jpe?g|png|bmp|gif)",
        risk = 6.0,
        mitre = {"T1083", "T1005"}
    },
    COPY_IMAGES = {
        pattern = "(?:cp|mv|scp|rsync)\\s+[\\s\\S]*\\.(?:jpe?g|png|bmp|gif)\\s+(?:/tmp|/var/tmp|/dev/shm)",
        risk = 6.5,
        mitre = {"T1074.001"}
    },
    PASSWORD_EXTRACT = {
        pattern = "(?:steghide|outguess|stegcracker)\\s+.*(?:-p\\s+|-passphrase\\s+|--password\\s+)",
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

local false_positive_patterns = {"(?:--help|--version|-h|-v)", "man\\s+(?:steghide|outguess|exiftool|binwalk)",
                                 "(?:apt-get|dpkg|yum|dnf)", "(?:test|example|sample|demo)"}

local function is_false_positive(cmd)
    for _, pattern in ipairs(false_positive_patterns) do
        if cmd:search(pattern) then
            return true
        end
    end
    return false
end

local function analyze_threat(cmd)
    cmd = cmd:lower()
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

    if event_type == "EXECVE" then
        local command = logline:gets("initiator.command.executed")
        local threat_type, risk, operation_type, mitre = analyze_threat(command)
        set_field_value(logline, "threat.type", threat_type)
        set_field_value(logline, "risk", risk)
        set_field_value(logline, "operation.type", operation_type)
        set_field_value(logline, "mitre", mitre)
        
        if threat_type then
            grouper1:feed(logline)
        end
    elseif event_type == "SYSCALL" then
        grouper1:feed(logline)
    end
end

function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_exec = nil
    local log_sys = nil
    
    if unique_events > 1 then
        for _, event in ipairs(events) do
            local ev_type = event:gets("observer.event.type")
            if ev_type == "SYSCALL" then
                log_sys = event
            elseif ev_type == "EXECVE" then
                log_exec = event
            end
        end

        if log_sys and log_exec then
            local mitre = log_exec:gets("mitre")
            local risk = log_exec:gets("risk")
            local operation_type = log_exec:gets("operation.type")
            local command = log_exec:gets("initiator.command.executed")

            if #command > 128 then
                command = command:sub(1,128).. "... "
            end

            alert({
                template = template,
                meta = {
                    observer_ip = log_exec:gets("observer.host.ip", "IP-адрес неопределён"),
                    observer_hostname = log_exec:gets("observer.host.hostname", "Имя узла неопределёно"),
                    observer_fqdn = log_exec:gets("observer.host.fqdn"),
                    user_name = log_sys:gets("initiator.user.name", "Пользователь неопределён"),
                    user_id = log_sys:gets("initiator.user.id", "Идентификатор пользователя неопределён"),
                    command_path = log_sys:gets("initiator.process.path.full", "Путь исполнения команды неопределён"),
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
                logs = events,
                mitre = mitre or {"T1001"},
                trim_logs = 10
            })
            grouper1:clear()
        end    
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)