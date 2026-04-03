-- Шаблон алерта
local template = [[
Подозрение на несанкционированное использование PowerShell в качестве интерпретатора вредоносных команд и скриптов.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{.Meta.command}}
Процесс: {{ .Meta.process}}
Тип угрозы: {{ .Meta.threat_caption}}   
]]

-- Параметры группера
local detection_window = "2m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "abuse.type"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения, шаблоны
local abuse_patterns = { 
--    suspicious_parameters = {
--        pattern = "-(?:e(nc)?(odedcommand)?|executionpolicy\\s+bypass|(?:windowstyle\\s+hidden)|no(?:logo|profile|(?:noninteractive|command_)))",
--        abuse_type = "Suspicious Parameters"
--    },
    
    ath_command_line = {
        pattern = "(-(?:commandlineswitchtype|encodedcommandparamvariation|useencodedarguments|encodedargumentsparamvariation|commandparamvariation)[\\s\\w]+){2,4}",
        abuse_type = "ATH PowerShell CommandLine Parameters"
    },
    sharphound = { 
        pattern = "<#\\s+(\\.(?:synopsis|description|parameter|example)[^\\[]+){3,10}#>\\s+[\\[\\]\\w\\s$=()]+param\\(.*\\[(?:string(\\[\\])?|switch|int)\\]\\s+\\$[^$\\s]+,\\s+\\[validaterange[,()\\d\\s]+\\].*\\$[^$\\s]+\\s+=\\s+[\'\"][\\w+\\/]{100,1000}",
        abuse_type = "SharpHound/BloodHound script attack"
    },
    reflection_load = {
        pattern = "(?:\\[system\\.reflection\\.assembly]::loadwithpartialname[\\s\\S]*?\\[windows\\.forms\\.clipboard]::(?:clear|gettext))|(?:\\[windows\\.forms\\.clipboard]::(?:clear|gettext).*?\\[system\\.reflection\\.assembly]::loadwithpartialname)",
        abuse_type = "Mimkatz Reflection.Load"
    },
    msxml_com = { --+
        pattern = "((?:bypass|iex)[^$]+)?(?:\\s+|\\$[^$]+)msxml(?:\\d+\\.\\w+|=[\\w\\s-]+comobject|\\.(?:open|send)|\\.responsetext)",
        abuse_type = "PowerShell MsXml COM object - with prompt"
    },
    xml_requests = {
        pattern = "bypass[^;]+new-object\\s+system\\.((xml)\\.?)+document[\\s\\S]+\\.xml[^\\.]+\\.command\\.\\w+\\.execute",
        abuse_type = "PowerShell XML requests"
    },
    invoke_mshta = {
        pattern = "((mshta\\.(?:exe|sct))[^;]+){2,10}\\.((?:exec|close)[();\'\"]+){2}",
        abuse_type = "Powershell invoke mshta.exe download"
    },
    ntfs_stream = { -- 1
        pattern = "get-content\\s+([^$]+)?-path\\s+\\$[^$]+\\\\w+\\.[^\\.\\s]{1,5}\\s+-stream[\\s\\w\'\";]+invoke-expression[$\\w\\s]+",
        abuse_type = "NTFS Alternate Data Stream Access"
    },
    posh_session_creation = {
        pattern = "(\\s+new-pssession\\s+-computername[^;]+[;\\w\\s{}-]+;){2}(\\s+(?:test-connection|(?:set|get)-content)\\s+[^;]+;)+",
        abuse_type = "PowerShell Session Creation and Use"
    },
    posh_command_execution = {
        pattern = "(?:powershell|pwsh)(\\.exe)?\\s+-e\\s+[^\\s]{100,1000}",
        abuse_type = "PowerShell Command Execution"
    },
    posh_maliciois_cmdlets = { 
        pattern = "(?:\"(?:(?:add|find|get|install|invoke|mount|new|out|remove|set)-(?:persistence(?:option)?|avsignature|gppautologon|gpppassword|httpstatus|keystrokes|securitypackages|vaultcredential|volumeshadowcopy|timedscreenshot|ssp|credentialinjection|dllinjection|mimikatz|ninjacopy|portscan|reflectivepeinjection|reversednslookup|shellcode|tokenmanipulation|wmicommand|compresseddll|encodedcommand|encryptedscript|minidump|comments|criticalprocess|masterbootrecord)|power(?:up|view))\"\\s*,\\s*){5,10}\"(?:(?:add|find|get|install|invoke|mount|new|out|remove|set)-(?:persistence(?:option)?|avsignature|gppautologon|gpppassword|httpstatus|keystrokes|securitypackages|vaultcredential|volumeshadowcopy|timedscreenshot|ssp|credentialinjection|dllinjection|mimikatz|ninjacopy|portscan|reflectivepeinjection|reversednslookup|shellcode|tokenmanipulation|wmicommand|compresseddll|encodedcommand|encryptedscript|minidump|comments|criticalprocess|masterbootrecord)|power(?:up|view))\"",
        abuse_type = "PowerShell Invoke Known Malicious Cmdlets"
    },
    powerup = { 
        pattern = "(\\[net\\.(?:servicepointmanager|securityprotocoltype)\\]::(?:securityprotocol|tls\\d+)[\\s=;]+){2}(i(?:ex|wr)[()\\s]){2}[\\w:\\/\\.]+power(?:up|sharp)\\.ps1",
        abuse_type = "PowerUp Invoke-AllChecks"
    },
    nslookup = {
        pattern = "(?:(?:function|powershell|system\\d+)\\s?[.\\s\\(]*nslookup[-\\s\'\"\\w\\.]*)[\\s\\S]+?(?:(?:function|powershell|system\\d+)\\s?[.\\s\\(]*nslookup[-\\s\'\"\\w\\.]*)",
        abuse_type = "Abuse Nslookup with DNS Records"
    },
    soaphound = { 
        pattern = "\\w+hound(\\.exe)?\\s+(--(?:user|password|domain|dc|bhdump|(build)?cache(filename)?|outputdirectory)\\s+([@\\w:$\\.,\\,()]+)?\\s*)+",
        abuse_type = "SOAPHound - Dump BloodHound Data, Build Cache"
    },
    posh_fireless_script = {
        pattern = "reg\\.exe\\s+add[\\s\\S]+iex[\\s\\S]+((\\[(?:text\\.encoding|convert)\\])::([\\w\\.]*(?:frombase64|get)string)[(]*){2,10}",
        abuse_type = "PowerShell Fileless Script Execution"

    },
    commands_winapi = {
        pattern = "((?:invoke-|iex|downloadstring|(?:win32_|start)Process)|(?:virtualalloc|createremotethread))(?:apppathbypass(\\.ps[1m])?|\\([\'\"]?[^\'\"]+[\'\"]?\\))",
        abuse_type = "PowerShell WinAPI commands"
    },
}

-- Стандартная функция анализа строки
local function analyze(cmd)
    local cmd = cmd:lower()

    for _, abuse_pattern in pairs(abuse_patterns) do
        local is_abuse = cmd:search(abuse_pattern.pattern) 
        
        if is_abuse then
            local abuse_type = abuse_pattern.abuse_type
            log("Abuse type:" ..abuse_type)
            return is_abuse,abuse_type 
        end
    end

    return false
end

-- Функция работы с логлайном
function on_logline(logline)
    local command_executed = logline:gets("initiator.command.executed")
    local is_abuse, abuse_type = analyze(command_executed)

    if is_abuse then
        set_field_value(logline, "abuse.type", abuse_type)
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local first_event = events[1]
    log("Events: " ..#events)
    if #events > 0 then
        local initiator_name = first_event:get("initiator.user.name") or "Пользователь не определён" 
        local host_ip = first_event:get("observer.host.ip") or first_event:get("reportchain.collector.host.ip") or "IP-адрес не определён"
        local host_name = first_event:get_asset_data("observer.host.hostname")
        local host_fqdn = first_event:get_asset_data("observer.host.fqdn")
        local service_name = first_event:get("target.service.name") or "Служба не определена"
        local command_executed = first_event:gets("initiator.command.executed")
        local process_path = first_event:get("initiator.process.path.full") or first_event:get("initiator.process.path.name") or first_event:get("evnt.logsource.application") or "Путь неопределён"
        local abuse_type = first_event:get("abuse.type")

        if #command_executed > 128 then
            command_executed = command_executed:sub(1, 128).. "... "
        end

         alert({
            template = template,
            meta = {
                user_name=initiator_name,
                command=command_executed,
                process=process_path,
                service=service_name,
                threat_caption=abuse_type,
                hostname=host_name,
                host_ip=host_ip,
                process=process_path
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
            mitre = {"T1059.001"},
            trim_logs = 10
            }
        )
       grouper1:clear()
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)

