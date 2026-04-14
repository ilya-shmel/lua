-- Шаблон алерта
local template = [[
Подозрение на наличие в системе Rootkit: Umbreon.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{ .Meta.command}}
Тип события: {{ .Meta.caption }}
]]

-- Параметры группера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Паттерны/регулярные выражения
local indicators = {
    umbreon_paths = {
        "/dev/shm/.umbreon",
        "/dev/shm/linux_software",
        "/run/shm/.X11-unix/",
        "/etc/ld.so.preload",
        "/usr/lib/libc.so"
    },
    umbreon_cmd_indicators = {
        "umbreon",
        ".umbreon",
        "linux_software",
        "ld.so.preload",
        "libc.so"
    },
    suspicious_processes = {
        "umbreon",
        "espeon",
        "hide"
    },
    malicious_hashes = {
        "b5e68f8e23115bdbe868d19d09c90eb535184acd",
        "73ddcd21bf05a9edc7c85d1efd5304eea039d3cb",
        "48a6e43af0cb40d4f92b38062012117081b6774e",
        "88aea4bb5e68c1afe1fb11d55a190dddb8b1586f",
        "73ddcd21bf05a9edc7c85d1efd5304eea039d3cb",
        "42802085c28c0712ac0679c100886be3bcf07341",
        "66d246e02492821f7e5bbaeb8156ece44c101bbc",
        "73ddcd21bf05a9edc7c85d1efd5304eea039d3cb",
        "4f6c6d42bdf93f4ccf68d888ce7f98bcd929fc72",
        "73ddcd21bf05a9edc7c85d1efd5304eea039d3cb",
        "1f1ab0a8e9ec43d154cd7ab39bfaaa1eada4ad5e",
        "81ad3260c0fc38a3b0f65687f7c606cb66c525a8",
        "7b10bf8187100cdc2e1d59536c19454b0c0da46f",
        "96d5e513b6900e23b18149a516fb7e1425334a44",
        "851b7f07736be6789cbcc617efd6dcb682e0ce54",
        "e2bc8945f0d7ca8986b4223ed9ba13686a798446",
        "17b42374795295f776536b86aa571a721b041c38",
        "394fae7d40b0c54c16d7ff3c3ff0d247409bd28f",
        "738ac5f6a443f925b3198143488365c5edf73679",
        "022be09c68a410f6bed15c98b63e15bb57e920a9",
        "3762c537801c21f68f9eac858ecc8d436927c77a",
        "2cd24c5701a7af76ab6673502c80109b6ce650c6",
        "358afd4bd02de3ce1db43970de5e4cb0c38c2848"
    }
}

-- Универсальная функция: возвращает true/false если проходит регулярка/паттерн
local function analyze (string, type)
    string = string:lower()
    log("Current string: " ..string)
    log("Type: " ..type)
    local comparation_type = "sub"
    local indicator_list = indicators[type]
    
    if type == "malicious_hashes" then
        comparation_type = "exact"
    end

    log("Inicator: " ..tostring(indicator_list).. ", String: " ..string.. ", Comparation type: " ..comparation_type)
    local is_pattern = contains(indicator_list, string, comparation_type)
    log("Is pattern: " ..tostring(is_pattern))

    if is_pattern then
        return true
    else
        return false
    end
end   

-- Функция обработки логлайна
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    local command_executed = logline:gets("initiator.command.executed")
    local target_sha1 = logline:gets("target.blacklist.file.sha1")
    local indicator_type = nil
    local is_sha_indicator = nil
    local is_command_indicator = nil

    if event_type == "EXECVE" then

        if #target_sha1 > 0 then
            is_sha_indicator = analyze(target_sha1, "malicious_hashes")
            indicator_type = "malicious_hashes"
        elseif #command_executed > 0 then    
            for indicator_name, _ in pairs(indicators) do
                is_command_indicator = analyze(command_executed, indicator_name)
                
                if is_command_indicator then
                    indicator_type = indicator_name
                    break
                end
                
            end
        end

        if is_sha_indicator or is_command_indicator then
           set_field_value(logline, "indicator.type", indicator_type)
           grouper1:feed(logline) 
        end
    elseif event_type == "SYSCALL" then
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
	local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_sys = nil
    local log_exec = nil

    if unique_events > 1 then
        log("Events counter: " ..#events)
        log("Unique events: " ..unique_events)
        local event_type = events[1]:gets("observer.event.type")
        log("Event type: " ..event_type)

        for _, event in ipairs(events) do
            local event_type = event:gets("observer.event.type")

            if event_type == "SYSCALL" then
                log_sys = event
            else
                log_exec = event
            end
        end

        local initiator_path = log_exec:gets("initiator.process.path.full")
        local command_executed = log_exec:get("initiator.command.executed") or "Команда отсутствует"
        local indicator_type = log_exec:gets("indicator.type")
        local initiator_name = log_sys:get("initiator.user.name") or "Пользователь неопределен"
        local malicious_hash = log_exec:get("target.blacklist.file.sha1") or "Для данного инцидента хэш отсутствует"
        local host_ip = log_sys:get("observer.host.ip") or "IP-адрес не определён"
        local host_name = log_sys:get("observer.host.hostname") or "Имя узла не определено"
        local host_fqdn = log_sys:get("observer.host.fqdn") or "FQDN узла не определено"
        if indicator_type == "malicious_hashes" then
            indicator_type = "Найден хэш файла Umbreon"
        else
            indicator_type = "Выполнение подозрительной команды в нестандартных директориях или копирование подозрительных файлов"
        end
        if #command_executed > 128 then
            command_executed = command_executed:sub(1,128).. "... "
        end
               
-- Функция алерта
        alert({
            template = template,
            meta = {
                user_name=initiator_name,
                command=command_executed,
                command_path=initiator_path,
                hash=malicious_hash,
                host_ip=host_ip,
                hostname=host_name,
                caption=indicator_type
                },
            risk_level = 10, 
            asset_ip = host_ip,
            asset_hostname = hostname,
            asset_fqdn = host_fqdn,
            asset_mac = "",
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "Rootkit",
            logs = events,
            mitre = {"T1014"},
            trim_logs = 10
            }
        )
        grouper1:clear()
    end    
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)