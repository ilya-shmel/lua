local create_incident = true
local assign_to_customer = false
local base_risk_score = 8.5

local template = [[Обнаружена обфускация команд

СИСТЕМНАЯ ИНФОРМАЦИЯ:
Узел: {{ if .First.observer.host.hostname }}"{{ .First.observer.host.hostname }}"{{ else if .First.observer.host.ip }}"{{ .First.observer.host.ip }}"{{ else }}"unknown"{{ end }}
IP: {{ if .First.observer.host.ip }}"{{ .First.observer.host.ip }}"{{ else }}"unknown"{{ end }}

ПОЛЬЗОВАТЕЛЬ:
{{ .Meta.user_name }}

ДЕТАЛИ ОБНАРУЖЕНИЯ:
Команда: {{ .Meta.command }}
Тип события: {{ .Meta.event_type }}
Тип обфускации: {{ .Meta.obfuscation_type }}
Платформа: {{ .Meta.platform }}
]]

local detection_patterns = {
    linux_base64_eval = {
        patterns = {"encoded%s*=%s*%$%(echo%s+['\"][^'\"]+['\"]%s*%);%s*eval%s+[\"']%$%(echo%s+%$encoded%s*|%s*base64%s+%-d%)[\"']",
                    "eval%s+[\"']%$%(echo%s+[^|]+%|%s*base64%s+%-d%)[\"']",
                    "encoded%s*=.*echo.*ZWNo.*eval.*echo%s+%$encoded.*base64%s*%-d",
                    "encoded%s*=%s*%$.*echo.*eval.*%$encoded.*base64%s*%-d"},
        weight = 1.0,
        name = "BASE64_EVAL_EXECUTION"
    },

    linux_python_base64 = {
        patterns = {"python3%s+%-.*<<.*EOF.*import%s+base64.*subprocess.*cmd%s*=%s*base64%.b64decode",
                    "python3.*import.*base64.*subprocess.*base64%.b64decode.*subprocess%.run",
                    "python.*%-c.*import%s+base64.*base64%.b64decode",
                    "python3.*%-.*<<.*EOF.*import.*base64.*subprocess.*b64decode.*subprocess%.run"},
        weight = 1.0,
        name = "PYTHON_BASE64_DECODE"
    },

    linux_rot13 = {
        patterns = {"echo%s+['\"]terrk['\"]%s*|%s*tr%s+['\"]A%-Za%-z['\"]%s+['\"]N%-ZA%-Mn%-za%-m['\"]%s*|%s*xargs.*bash%s+%-c",
                    "tr%s+['\"]A%-Za%-z['\"]%s+['\"]N%-ZA%-Mn%-za%-m['\"]",
                    "echo.*tr.*A%-Za%-z.*N%-ZA%-Mn%-za%-m.*password",
                    "echo.*terrk.*tr.*A%-Za%-z.*N%-ZA%-Mn%-za%-m.*xargs.*bash",
                    "tr.*A%-Za%-z.*N%-ZA%-Mn%-za%-m.*password.*passwd"},
        weight = 1.0,
        name = "ROT13_CIPHER"
    },

    linux_variable_concat = {
        patterns = {"A%s*=%s*g%s*;%s*B%s*=%s*rep%s*;%s*C%s*=.*;%s*D%s*=%s*pass%s*;%s*E%s*=%s*word%s*;.*%$A%$B%$C%$D%$E",
                    "[A-Z]%s*=%s*[a-z]+%s*;.*[A-Z]%s*=%s*[a-z]+%s*;.*[A-Z]%s*=%s*[a-z]+%s*;.*%$[A-Z]%$[A-Z]%$[A-Z]%$[A-Z]%$[A-Z]",
                    "%$A%$B%$C%$D%$E", "A=g;.*B=rep;.*C=.*;.*D=pass;.*E=word;.*%$A%$B%$C%$D%$E",
                    "[A-Z]=[a-z];[A-Z]=[a-z];[A-Z]=[a-z];[A-Z]=[a-z];[A-Z]=[a-z];.*%$[A-Z]%$[A-Z]%$[A-Z]%$[A-Z]%$[A-Z]"},
        weight = 1.0,
        name = "VARIABLE_CONCATENATION"
    },

    linux_wget_execution = {
        patterns = {"bash%s+%-c%s+[\"']%$%(wget%s+%-qO%-.*echo%s+['\"][^'\"]*['\"]%s*|%s*base64%s+%-d%)[\"']",
                    "wget%s+%-qO%-.*http.*echo.*base64%s*%-d.*bash", "wget.*malicious.*echo.*base64%s*%-d",
                    "bash.*wget.*%-qO%-.*echo.*base64%-d", "wget.*%-qO.*http.*echo.*base64.*%-d"},
        weight = 1.0,
        name = "WGET_REMOTE_EXECUTION"
    },

    linux_hex_bash = {
        patterns = {"bash%s+%-c%s+%$'\\x[0-9a-fA-F][0-9a-fA-F]\\x[0-9a-fA-F][0-9a-fA-F]\\x[0-9a-fA-F][0-9a-fA-F]",
                    "%$'\\x67\\x72\\x65\\x70", "bash%s+%-c%s+%$'\\x", "bash.*%-c.*%$.*\\x[0-9a-fA-F][0-9a-fA-F]",
                    "%$'\\x[0-9a-fA-F][0-9a-fA-F]\\x[0-9a-fA-F][0-9a-fA-F]"},
        weight = 1.0,
        name = "HEX_BASH_ESCAPE"
    },

    linux_perl_base64 = {
        patterns = {"perl%s+%-MMIME::Base64%s+%-e%s+exec%s+decode_base64", "perl.*MMIME.*Base64.*decode_base64",
                    "exec%s+decode_base64%s*%([\"'][^'\"]*[\"']%)", "perl.*%-MMIME::Base64.*%-e.*exec.*decode_base64",
                    "perl%-MMIME::Base64%-e.*decode_base64"},
        weight = 1.0,
        name = "PERL_BASE64_EXECUTION"
    },

    linux_xxd_decode = {
        patterns = {"echo%s+['\"][0-9a-fA-F%s:]+['\"]%s*|%s*xxd%s+%-r%s+%-p%s*|%s*bash", "xxd%s+%-r%s+%-p.*bash",
                    "echo.*[0-9a-fA-F]+.*xxd%s*%-r", "echo.*676572.*xxd.*%-r.*%-p.*bash", "echo.*xxd%-r%-p.*bash"},
        weight = 1.0,
        name = "XXD_HEX_DECODE"
    },

    linux_ld_preload = {
        patterns = {"export%s+LD_PRELOAD%s*=.*%.so", "LD_PRELOAD%s*=.*%.so.*cat%s+/etc/shadow",
                    "export.*LD_PRELOAD.*shadow", "export.*LD_PRELOAD.*%.so.*cat.*shadow", "LD_PRELOAD=.*%.so"},
        weight = 1.0,
        name = "LD_PRELOAD_INJECTION"
    },

    linux_general_obfuscation = {
        patterns = {"eval.*base64", "echo.*base64%-d", "base64.*%-d.*exec", "bash%-c.*base64",
                    "python.*base64%.b64decode", "perl.*base64", "tr.*A%-Za%-z.*N%-ZA%-M", "xxd%-r", "LD_PRELOAD=",
                    "wget.*bash", "curl.*bash", "\\x[0-9a-fA-F][0-9a-fA-F]", "%$[A-Z]%$[A-Z]%$[A-Z]"},
        weight = 0.8,
        name = "GENERAL_OBFUSCATION"
    },

    windows_powershell_encoded = {
        patterns = {"powershell.*%-encodedcommand", "powershell.*%-enc%s+[A-Za-z0-9+/=]{20,}",
                    "powershell.*%-e%s+[A-Za-z0-9+/=]{20,}", "%[convert%]::frombase64string",
                    "%[system%.text%.encoding%]::utf8%.getstring%(%[system%.convert%]::frombase64string",
                    "powershell%-e[A-Za-z0-9+/=]+", "powershell%-encodedcommand[A-Za-z0-9+/=]+"},
        weight = 1.0,
        name = "POWERSHELL_ENCODED_COMMAND"
    },

    windows_powershell_obfuscation = {
        patterns = {"powershell.*%-windowstyle%s+hidden.*%-executionpolicy%s+bypass",
                    "powershell.*%-noprofile.*%-command",
                    "iex%s*%(%s*new%-object%s+net%.webclient%s*%)%.downloadstring",
                    "invoke%-expression.*downloadstring", "invoke%-expression.*%[convert%]",
                    "powershell.*%-w%s+h.*%-ep%s+b", "powershell.*hidden.*bypass"},
        weight = 0.9,
        name = "POWERSHELL_OBFUSCATION"
    },

    windows_batch_obfuscation = {
        patterns = {"for%s+/f%s+[\"']tokens%s*=%s*[0-9,%-*]+[\"'].*do",
                    "set%s+[a-zA-Z_][a-zA-Z0-9_]*%s*=.*&%s*set%s+[a-zA-Z_][a-zA-Z0-9_]*%s*=.*&.*%![a-zA-Z_][a-zA-Z0-9_]*!%![a-zA-Z_][a-zA-Z0-9_]*!",
                    "call%s*:%s*[a-zA-Z_][a-zA-Z0-9_]*", "certutil%s+%-decode.*%s+%-f", "cmd/c.*&.*&",
                    "%![a-zA-Z_]+!%![a-zA-Z_]+!"},
        weight = 0.8,
        name = "BATCH_OBFUSCATION"
    },

    windows_wmi_execution = {
        patterns = {"wmic%s+process%s+call%s+create%s+[\"']cmd%s+/c%s+powershell",
                    "wmic%s+process%s+call%s+create.*base64", "get%-wmiobject.*win32_process.*invoke%-wmimethod",
                    "wmic.*process.*call.*create", "invoke%-wmimethod.*win32_process"},
        weight = 0.9,
        name = "WMI_CODE_EXECUTION"
    },

    windows_lolbins = {
        patterns = {"rundll32%s+javascript:[\"'].*[\"']", "rundll32.*url%.dll.*fileprotocolhandler",
                    "regsvr32%s+/s%s+/n%s+/u%s+/i:.*scrobj%.dll", "mshta%s+javascript:.*", "mshta%s+vbscript:.*",
                    "installutil%s+/logfile%s*=%s*.*%.cmdline", "certutil%s+%-urlcache%s+%-split%s+%-f%s+http",
                    "rundll32.*javascript:", "mshta.*javascript:", "regsvr32.*scrobj%.dll"},
        weight = 1.0,
        name = "LOLBINS_ABUSE"
    },

    windows_fileless = {
        patterns = {"%[reflection%.assembly%]::load%s*%(", "reflection%.assembly.*loadwithpartialname",
                    "invoke%-expression.*new%-object.*net%.webclient", "iex.*new%-object.*system%.net%.webclient",
                    "add%-type.*%-memberdefinition.*virtualalloc", "%[reflection%.assembly%]::load",
                    "loadwithpartialname"},
        weight = 1.0,
        name = "FILELESS_EXECUTION"
    },

    windows_process_injection = {
        patterns = {"virtualalloc.*writeprocessmemory.*createremotethread", "ntcreatethreadex",
                    "queueuserapc.*ntqueueapcthread", "%[system%.runtime%.interopservices%.marshal%]::copy",
                    "virtualalloc", "writeprocessmemory", "createremotethread"},
        weight = 1.0,
        name = "PROCESS_INJECTION"
    },

    windows_registry_manipulation = {
        patterns = {"reg%s+add.*hklm.*run", "reg%s+add.*hkcu.*run", "new%-itemproperty.*hklm.*run",
                    "new%-itemproperty.*hkcu.*run", "set%-itemproperty.*run", "reg.*add.*run"},
        weight = 0.8,
        name = "REGISTRY_MANIPULATION"
    }
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

local function safe_string_find(text, pattern)
    local success, result = pcall(string.find, string.lower(text), string.lower(pattern))
    if success and result then
        return true
    end
    success, result = pcall(string.find, text, pattern)
    return success and result
end

--local function detect_platform(logline)
--    local fields_to_check = {logline:gets("observer.os.name"), logline:gets("observer.os.family"),
--                             logline:gets("initiator.process.name"), logline:gets("event.application.name"),
--                             logline:gets("event.logsource.product"), logline:gets("event.logsource.vendor") }
--
--    local combined = string.lower(table.concat(fields_to_check, " "))
--
--    if string.find(combined, "windows") or string.find(combined, "powershell") or string.find(combined, "cmd") or
--        string.find(combined, "pwsh") or string.find(combined, "microsoft") then
--        return "windows"
--    elseif string.find(combined, "linux") or string.find(combined, "unix") or string.find(combined, "bash") or
--        string.find(combined, "sh") or string.find(combined, "debian") or string.find(combined, "ubuntu") then
--        return "linux"
--    end
--
--    return "unknown"
--end

-- Это переделать
local function analyze_command(command, platform)
    local detected_patterns = {}
    local total_weight = 0
    local primary_type = "UNKNOWN"

    for pattern_name, pattern_data in pairs(detection_patterns) do
        local is_platform_match = false

        if platform == "linux" and string.find(pattern_name, "linux_") then
            is_platform_match = true
        elseif platform == "windows" and string.find(pattern_name, "windows_") then
            is_platform_match = true
        elseif platform == "unknown" then
            is_platform_match = true
        end

        if is_platform_match then
            for _, pattern in ipairs(pattern_data.patterns) do
                if safe_string_find(command, pattern) then
                    table.insert(detected_patterns, pattern_data.name)
                    total_weight = total_weight + pattern_data.weight
                    if #detected_patterns == 1 then
                        primary_type = pattern_data.name
                    end
                    break
                end
            end
        end
    end

    return detected_patterns, total_weight, primary_type
end

local function is_legitimate(command)
    for _, exclusion in ipairs(legitimate_exclusions) do
        if safe_string_find(command, exclusion) then
            return true
        end
    end

    for _, exclusion in ipairs(system_exclusions) do
        if safe_string_find(command, exclusion) then
            return true
        end
    end

    local hash_count = 0
    for _ in string.gmatch(command, "[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]") do
        hash_count = hash_count + 1
        if hash_count > 10 then
            return true
        end
    end

    return false
end

-- Функция обработки логлайна
function on_logline(logline)
    local command_fields = {logline:gets("initiator.command.executed"), logline:gets("target.process.command_line"),
                            logline:gets("initiator.process.command_line"), logline:gets("event.command"),
                            logline:gets("process.command_line")}
    local user_fields = {logline:gets("initiator.user.name"), logline:gets("initiator.auth.user.name"),
                         logline:gets("target.user.name"), logline:gets("user.name"), logline:gets("event.user")}
    local command = nil
    
    for _, field in ipairs(command_fields) do
        if #field > 5 then
            command = field
            break
        end
    end

    local user_name = "unknown"
    for _, field in ipairs(user_fields) do
        if field then
            user_name = field
            break
        end
    end

    if is_legitimate(command) then
        return
    end

    local platform = detect_platform(logline)
    local detected_patterns, weight, primary_type = analyze_command(command, platform)

    if #detected_patterns == 0 then
        return
    end

    if final_score < threshold then
        return
    end

    local meta = {
        user_name = user_name,
        command = command,
        event_type = "CODE_OBFUSCATION",
        obfuscation_type = primary_type,
        platform = platform,
        risk_level = risk_level,
        threat_indicators = threat_indicators,
        total_events = "1",
        detection_method = "UniversalObfuscationDetector_v5"
    }

    alert({
        template = template,
        risk_level = base_risk_score,
        asset_ip = logline:get_asset_data("observer.host.ip"),
        asset_hostname = logline:get_asset_data("observer.host.hostname"),
        asset_fqdn = logline:get_asset_data("observer.host.fqdn"),
        create_incident = create_incident,
        assign_to_customer = assign_to_customer,
        logs = {logline},
        meta = meta,
        mitre = mitre_techniques,
        trim_logs = 1
    })
end
