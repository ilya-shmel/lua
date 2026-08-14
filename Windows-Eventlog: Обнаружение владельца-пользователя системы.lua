-- Шаблон алерта
local template = [[
{{ .Meta.title }}.

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{ or .Meta.ip "IP-адрес не определён" }}
Узел: {{ or .Meta.hostname "Имя узла не определено" }}
FQDN: {{ or .Meta.fqdn "FQDN узла не определено" }}

ИНИЦИАТОР:
Пользователь: {{ or .Meta.user "Пользователь не определён"}}

ВЫПОЛНЕННАЯ КОМАНДА:
{{ .Meta.command }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "observer.process.id"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Шаблоны и паттерны
command_patterns = {
    {
        cmdlet = [[(?:^|"|'|;|\s+|\\|\/)get-itemproperty(?:$|\s+|;|'|")]],
        parameters = {"hklm:\\software\\microsoft\\enrollments", "hklm:\\software\\microsoft\\identitystore\\logoncache\\", "hklm:\\software\\microsoft\\provisioning\\autopilotsettings", "registeredowner", "registeredorganization"} 
    },
    {
        cmdlet = [[(?:^|"|'|;|\s+|\\|\/)get-ciminstance(?:$|\s+|;|'|")]],
        parameters = {"registereduser", ".domain", ".hostname", "win32_loggedonuser", "mdm_devdetail_ext", "root/cimv2/mdm/dmmap", "dcim_assetinformation", "root/dcim/sysman", "win32_systemenclosure"} 
    },
    {
        cmdlet = [[(?:^|"|'|;|\s+|\\|\/)get-service(?:$|\s+|;|'|")]],
        parameters = {"ccmexec"}
    },
    {
        cmdlet = [=[(?:^|"|'|;|\s+|\\|\/)\[system.(?:security.principal.windowsidentity|net.dns)\](?:$|\s+|:|'|")]=],
        parameters = {"getcurrent().name", "gethostbyname", ".hostname"}
    },
    {
        cmdlet = [[(?:^|"|'|;|\s+|\\|\/)(?:whoami\s+\/cloud|gpresult\s+\/r|\$env:(?:computername|username)|query\s+user|manage-bde\s+-protectors\s+-get\s+c:)(?:$|\s+|:|'|")]]
    }
}

-- Вспомогательная функция логирования значений
local function log_results(function_name, debug_info)
    log("=== function " .. function_name .. " ===")
    log("Table elements: " .. #debug_info)
    
    for _, line in ipairs(debug_info) do
        local label = line[1]
        local value = line[2]
        log(label .. tostring(value))
    end    
end

-- Функция алерта
local function alert_function(events, meta)
    alert({
        template = template,
        meta = meta,
        risk_level = meta.risk,
        asset_ip = meta.ip,
        asset_hostname = meta.hostname,
        asset_fqdn = meta.fqdn,
        asset_mac = "",
        create_incident = true,
        incident_group = "",
        assign_to_customer = false,
        incident_identifier = "",
        logs = events,
        mitre = meta.risk,
        trim_logs = 10
        }
     )
end

-- Функция сокращения строки для алерта
local function string_cut(cmd)
    if #cmd > 256 then
        cmd = cmd:sub(1, 256).. "... "
    end

    return cmd
end

-- Функция обработки логлайна
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")

    if compare(event_id, "==", "4104") then
        local command_executed = logline:gets("initiator.command.executed"):lower()
        
        for _, pattern in ipairs(command_patterns) do
            if command_executed:search(pattern.cmdlet) then
                if pattern.parameters then
                    if contains(pattern.parameters, command_executed, "sub") then
                        grouper1:feed(logline)
                    end
                else
                    grouper1:feed(logline)
                end
            end
        end
    else
        grouper1:feed(logline)
    end
end

-- Функция группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_scriptblock = {}
    local log_module = {}
    local commands = {}
    
    if unique_events > 1 then
        for _, event in ipairs(events) do
            local event_id = event:gets("observer.event.id")

            if compare(event_id, "==", "4104") then
                table.insert(log_scriptblock, event)
                table.insert(commands, event:gets("initiator.command.executed"))
            else
                table.insert(log_module, event)
            end
        end
        
        if #log_scriptblock > 1 and #log_module > 0 then
            local first_scriptblock_event = log_scriptblock[1]
            local first_module_event = log_module[1]
            local meta = {
                user=first_module_event:gets("initiator.user.name"),
                command=string_cut(table.concat(commands, "; ")),
                ip=first_scriptblock_event:gets("observer.host.ip"),
                hostname=first_scriptblock_event:gets("observer.host.hostname"),
                fqdn=first_scriptblock_event:gets("observer.host.fqdn"),
                risk=5.0,
                mitre={"T1033"},
                title="Выполнены команды для обнаружения владельца/пользователя системы"            
            }

            alert_function(events, meta)
            grouper1:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)