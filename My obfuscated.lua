-- Шаблон алерта
local template = [[
	Обнаружена обфускация команд.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор выполнения): {{ .Meta.user_name }}
    Команда: {{ .Meta.command }}
    Путь исполнения: {{ .Meta.command_path }}
    Платформа: {{ .Meta.platform }}
     
]]

local prefix = "(?:^|\\/|\\s+|\"|\')"

local detection_patterns_linux = {
    prefix.. "\\w+(\\s+)?=\\$\\([\\w\"\'=\\s]+\\);\\s+eval\\s+[\'\"\\]{1,2}\\$\\([\\w\\s$\'\"]+\\|base64\\s+-d\\)",
    prefix.. "python[\\d\\.]{1,4}\\s+-\\s+<<[\'\"\\w\\s]+import\\s+base64,[\\s\\w=]+base64\\.b64decode[\\(\'\"]{1,2}[^\\s]+[\'\"\\)]{1,2}\\s+subprocess\\.run[\\(\\)\\.\\w\\s]+EOF",
    prefix.. "export\\s+\\w+=[$`(]+\\w+\\s+[\'\"](\\/?[^\\/\\s])+[\'\"]\\s+?\\|\\s+?tr[-\\s\\w\'\"\\\\]+[);]+\\s+?(\\w+\\s+)+(\\/?[^\\/\\s])+",
    prefix.. "\\w+\\s+[\\\'\"]+[\\d,a-f]+\\s+[\\w:!@=]+[\\\'\"]+\\s+?\\|\\s+?xxd\\s+[-\\w=\\s]+",
    prefix.. "[$`][\'\"](\\\\{2}x[\\d,a-f]{2})+[\'\"]",
    prefix.. "(\\w+=[^;]+;\\s+){3,10}(\\$\\w+){1,10}\\s+(\\/?[^\\/\\s]+\\/?)+",
    prefix.. "(?:wget|curl|lwp-download)\\s[-\\w\\s:\\/`$\'\"]+\\|\\s+base64\\s+-d",
    prefix.. "[^|]+\\|\\s+?tr[-\'\"\\s\\w]+\\|\\s+?xargs\\s+-\\w({}\\s+[^{}]+)+",
    prefix.. "perl\\s+[-\\s:\\w]+exec\\s+decode_base64\\([^()]+\\)",
}

local detection_patterns_windows = {
    prefix.. "p(o)?w(er)?sh(ell)?\\s+-command\\s+[\'\"\\\\]+\\[convert\\]::frombase64string[(\'\"]+\\w+[)\'\"]+\\s+?\\|\\s+?foreach-object\\s+[{}\\[\\]$\\w]+[\"\'\\\\]+",
    prefix.. "certutil\\s+-decode(\\s+\\w:(\\[^\\s\\]+)+){2}",
    prefix.. "cscript\\s+\\/{2}\\w+\\s+\\w+\\.js\\s+[-\'\"\\w=@:]+\\s+\\w:(\\[^\\]+)+",
    prefix.. "openssl\\s+base64\\s+-d(\\s+-\\w+\\s+[-\\w\\.=\\\\]+)+",
} 
local sensitive_indicators = {"/etc/passwd", "/etc/shadow", "/etc/gshadow", "password", "passwd", "pwd",
                              "/var/log/auth.log", "/var/log/secure", "/root/", "/home/",
                              "c:\\windows\\system32\\config\\sam", "c:\\windows\\system32\\config\\security",
                              "ntds.dit", "lsass.exe", "lsass.dmp", "mimikatz", "sekurlsa", "hklm\\sam",
                              "hklm\\security", "hklm\\system", "credential", "secret", "token", "key"}

local legitimate_exclusions = {"ansible", "puppet", "chef", "salt", "terraform", "docker", "systemd", "visual studio",
                               "vscode", "jetbrains", "office", "chrome", "firefox", "microsoft", "windows defender",
                               "antimalware", "update", "git", "npm"}

local system_exclusions = {"/usr/lib/", "/lib/systemd/", "/var/lib/", "/opt/", "c:\\windows\\system32\\",
                           "c:\\windows\\syswow64\\", "c:\\program files\\", "c:\\program files (x86)\\"}

-- Переменные для групперов
local detection_window = "1m"
local grouped_time_field = "@timestamp,RFC3339"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by1 = {"observer.event.type"}
local aggregated_by2 = {"target.image.name"}


-- Универсальная функция: возвращает true/false если проходит регулярка/поиск
local function analyze(cmd, platform)
    local cmd_string = cmd:lower()
    
    if platform == "linux" then
        for _, pattern in pairs(detection_patterns_linux) do
            local is_pattern = cmd_string:search(pattern)

            if is_pattern then
                return is_pattern
            end
        end
    else
        for _, pattern in pairs(detection_patterns_windows) do
            local is_pattern = cmd_string:search(pattern)

            if is_pattern then
                return is_pattern
            end
        end
    end

    for _, indicator in pairs(sensitive_indicators) do
        local is_path = cmd_string:match(indicator)
        if is_path then
            return is_path
        end
    end

    return false
end

-- Функция алерта
local function alert_function(cmd, user, path, ip, hostname, fqdn, events, platform)
    alert({
            template = template,
            meta = {
                user_name=user,
                command=cmd,
                command_path=path,
                platform=platform
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
            mitre = {"T1140"},
            trim_logs = 10
            }
        )
end

-- Функция поиска легитимных маркеров
local function is_legitimate(path_name)
    local legitimate = false

    for _, binary in ipairs(legitimate_exclusions) do
        local exclusion_flag = path_name:match(binary) or ""
        
        if exclusion_flag:match("%S+") then
            legitimate = true
        end
    end

    for _, path in pairs(system_exclusions) do
        local is_path = path_name:match(path) or ""
        
        if is_path:match("%S+") then
            legitimate = true
        end
    end

    return legitimate
end

-- Функция работы с логлайном
function on_logline(logline)
    local logsource = logline:gets("event.logsource.product") 
    local vendor = logline:gets("event.logsource.vendor")
    local command_executed = logline:gets("initiator.command.executed")

    if logsource == "linux" then
        local event_type = logline:gets("observer.event.type")
        
        if event_type == "EXECVE" then
            local is_obfuscated = analyze(command_executed, "linux")
            if is_obfuscated then
                grouper_linux:feed(logline)
            end
        else 
            local path_name = logline:gets("initiator.process.path.name")
            local is_exclusion = is_legitimate(path_name) 
            
            if is_exclusion then
                return
            end
            grouper_linux:feed(logline)
        end
    elseif vendor == "microsoft" then
        local image_name = logline:gets("target.process.path.full")
        local is_exclusion = is_legitimate(image_name)

        if is_exclusion then
            return
        end

        local is_obfuscated = analyze(command_executed, "windows")
           
        if is_obfuscated then
            grouper_windows:feed(logline)
        end
    end
end

-- Функция сработки группера для Linux
function on_grouped_linux(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_sys = nil
    local log_exec = nil

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_type = event:gets("observer.event.type")            
            if  event_type == "SYSCALL" then
                log_sys = event
            else
                log_exec = event
            end
        end

        if log_sys and log_exec then
            local current_command = log_exec:gets("initiator.command.executed")
            local user_name = log_sys:get("initiator.user.name") or "Не установлен"
            local path_name = log_sys:gets("initiator.process.path.full")
            local host_ip = log_exec:gets("observer.host.ip")
            local host_name = log_exec:gets("observer.host.hostname")
            local host_fqdn = log_exec:gets("observer.host.fqdn")

            if #current_command > 128 then
                current_command = current_command:sub(1,128).. "..."
            end

            alert_function(current_command, user_name, path_name, host_ip, host_name, host_fqdn, events, "Linux")
            grouper_linux:clear()
        end
    end 
end

-- Функция сработки группера для Windows
function on_grouped_windows(grouped)
    local events = grouped.aggregatedData.loglines
    
    if #events >= 1 then
        local current_command = events[1]:gets("initiator.command.executed")
        local user_name = events[1]:get("initiator.user.name") or "Не установлен"
        local path_name = events[1]:gets("initiator.process.path.full") or events[1]:gets("target.process.path.full")
        local host_ip = events[1]:gets("observer.host.ip")
        local host_name = events[1]:gets("observer.host.hostname")
        local host_fqdn = events[1]:gets("observer.host.fqdn")

        if #current_command > 128 then
            current_command = current_command:sub(1,128).. "..."
        end

        alert_function(current_command, user_name, path_name, host_ip, host_name, host_fqdn, events, "Windows")
        grouper_windows:clear()
    end
end

grouper_linux = grouper.new(grouped_by, aggregated_by1, grouped_time_field, detection_window, on_grouped_linux)
grouper_windows = grouper.new(grouped_by, aggregated_by2, grouped_time_field, detection_window, on_grouped_windows)