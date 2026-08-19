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
Задействованные объекты: {{ or .Meta.object "Оббъекты не зафиксированы" }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "observer.process.id"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Шаблоны и паттерны
local power_patterns = {
    {
        main_pattern = [[(?:^|"|'|;|\s+|\\|\/)powerview\.ps1(?:$|\s+|;|'|")]]
    },
    {
        main_pattern = [[(?:^|"|'|;|\s+|\\|\/)get-net(?:$|\s+|;|'|")]],
        cmdlets = {"get-netdomain", "get-netdomaincontroller", "get-netforest", "get-netforestdomain", "get-netforestcatalog", "get-netuser", "get-netcomputer", "get-netou", "get-netsite", "get-netsubnet", "get-netgroup", "get-netgroupmember", "get-netfileserver", "get-netgpo", "get-netgpogroup", "get-netcomputersitename", "get-netprocess", "get-netdomaintrust", "get-netforesttrust"}
    },
    {
        main_pattern = [[(?:^|"|'|;|\s+|\\|\/)invoke-\w+(?:$|\s+|;|'|")]],
        cmdlets = {"invoke-aclscanner", "invoke-checklocaladminaccess", "invoke-threadedfunction", "invoke-userhunter", "invoke-processhunter", "invoke-eventhunter", "invoke-sharefinder", "invoke-filefinder", "invoke-enumeratelocaladmin", "invoke-mapdomaintrust"}
    },
    {
        main_pattern = [[(?:^|"|'|;|\s+|\\|\/)find-\w+(?:$|\s+|;|'|")]],
        cmdlets = {"find-interestingdomainacl", "find-managedsecuritygroups", "find-gpolocation", "find-gpocomputeradmin", "find-domainuserlocation", "find-domainprocess", "find-domainuserevent", "find-domainshare", "find-interestingdomainsharefile", "find-domainlocalgroupmember", "find-foreignuser", "find-foreigngroup"}
    },
    {
        main_pattern = [[(?:^|"|'|;|\s+|\\|\/)convert-?\w+(?:$|\s+|;|'|")]],
        cmdlets = {"convert-nametosid", "convertto-sid", "convert-sidtoname", "convertfrom-sid"}
    },
    {
        main_pattern = [=[(?:^|"|'|;|\s+|\\|\/)get-[^n]\w+(?:$|\s+|;|'|")]=],
        cmdlets = {"get-ipaddress", "get-domainspnticket", "get-dnszone", "get-dnsrecord", "get-userevent", "get-adobject", "get-objectacl", "get-guidmap", "get-dfsshare", "get-loggedonlocal", "get-sitename", "get-proxy", "get-lastloggedon", "get-cachedrdpconnection", "get-registrymounteddrive", "get-domainpolicy", "get-domainpolicydata"}
    },
    {
        main_pattern = [[(?:^|"|'|;|\s+|\\|\/)(?:request|add|resolve|convert(?:to|from)|set|test|new)-\w+(?:$|\s+|;|'|")]],
        cmdlets = {"request-spnticke", "add-objectacl", "add-domainobjectacl", "resolve-ipaddress", "convertto-sid", "convertfrom-sid", "set-domainobject", "test-adminaccess", "new-threadedfunction"}
    }
}

local script_text_markers = {"param%s*%(", "foreach%s*%(", "try%s*{", "add%-member", "write%-verbose", "function%s+"}

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

local function is_script_text(cmd)
    local marker_count = 0
    local var_count = 0

    if #cmd > 400 then return true -- Проверяем число символов
    elseif #cmd > 200 then
          
        for _, marker in ipairs(script_text_markers) do -- Считаем признаки скрипта
            if cmd:match(marker) then
                marker_count = marker_count + 1
            end
        end

        for _ in cmd:gmatch("%$[%w_]+") do -- Считаем переменные
            var_count = var_count + 1
        end
    end
    
    if cmd:search("adspath") then
        local diag_info = {
            {"Command's length: ", #cmd},
            {"Markers count: ", marker_count},
            {"Variables count: ", var_count}
        }

        log_results("is_script_text", diag_info)
    end

    if marker_count > 1 and var_count > 9 then return true end

    return false

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
    if #cmd > 128 then
        cmd = cmd:sub(1, 128).. "... "
    end

    return cmd
end

-- Функция обработки логлайна
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")

    if compare(event_id, "==", "4104") then
        local command_executed = logline:gets("initiator.command.executed"):lower()
        
        for _, pattern in ipairs(power_patterns) do
            if command_executed:search(pattern.main_pattern) then
                if pattern.cmdlets and not is_script_text(command_executed) then
                    if contains(pattern.cmdlets, command_executed, "sub") then grouper1:feed(logline) end
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
    local commands = {}
    local log_module    
    
    if unique_events > 1 then
        for _, event in ipairs(events) do
            if compare(event:gets("observer.event.id"), "==", "4104") then
                table.insert(log_scriptblock, event)
                table.insert(commands, event:gets("initiator.command.executed"))
            else
                log_module = event
            end
        end
        
        if #log_scriptblock > 0 and log_module then
            local scriptblock_first_event = log_scriptblock[1]
            local meta = {
                user=log_module:gets("initiator.user.name"),
                command=string_cut(table.concat(commands, "; ")),
                object=log_module:gets("target.object.name"),
                ip=scriptblock_first_event:gets("observer.host.ip"),
                hostname=scriptblock_first_event:gets("observer.host.hostname"),
                fqdn=scriptblock_first_event:gets("observer.host.fqdn"),
                risk=8.0,
                mitre={"T1033"},
                title="Обнаружено использование скрипта PowerView.ps1 — часть набора утилит PowerSploit"            
            }

            alert_function(events, meta)
            grouper1:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)