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
Выполненные командлеты и параметры: 
{{ .Meta.commandlets }};
{{ .Meta.objects }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "event.rule.description"}
local aggregated_by = {"target.object.name"}
local grouped_time_field = "@timestamp,RFC3339"

-- Шаблоны и паттерны
local target_objects_patterns = {
    {   
        cmdlets = {"get-wmiobject", "get-ciminstance"},   
        parameters = {"msacpi_thermalzonetemperature", "class win32_computersystem", "win32_computersystem", "win32_logicaldisk", "win32_processor", "win32_physicalmemory", "win32_bios", "win32_baseboard", "win32_videocontroller", "win32_operatingsystem", "win32_product", "win32_networkadapter", "win32_systemenclosure", "win32_sounddevice", "win32_desktopmonitor", }
    },
    {
        cmdlets = {"get-process"},
        parameters = {"vbox", "vmware", "vmtoolsd", "vboxservice", "vmwaretray", "vmacthlp", "vboxtray", "vmsrvc", "df5serv", "prl_tools"}
    },
    {
        cmdlets = {"test-path"},
        parameters = {"vmsmb", "vboxminirdrdn", "cdrom0"}
    },
    {
        cmdlets = {"get-service"},
        parameters = {"vmtools", "vmdebug", "vmmouse", "vmmemctl", "vmhgfs", "vboxguest", "vboxservice", "vboxsf", "vboxmouse", "vmicheartbeat", "vmicvss", "vmicshutdown", "vmiexchange", "vmcompute", "hvhost", "vmsrvc"}
    },
    {
        cmdlets = {"start-sleep"},
        parameters = {"300", "300000", "30000", "180"}
    },
    {
        cmdlets = {"test-connection", "get-netroute"},
        parameters = {"1", "0.0.0.0/0"}
    },
    {
        cmdlets = {"add-type"},
        parameters = {"gettickcount", "createmutex", "waitforsingleobject"}
    },
}
local command_line_patterns = {
    {
        command = [=[(?:^|\s+|"|'|\\)wmic(\.exe)?[\s"':;][\s\w\/\\:'"]*get\s+]=],
        parameters = {"cpu", "memorychip", "bios", "baseboard", "nic", "virtualization", "virtualsystemsettingdata"}
    },
    {
        command = [=[(?:^|\s+|"|'|\\)tasklist\s*|\s*findstr[\s"':;]]=],
        parameters = {"vmms", "vmwp", "qemu-ga", "hyper-v", "vmtoolsd", "vboxservice"}
    },
    {
        command = [=[(?:^|\s+|"|'|\\)reg\s+query[\s"':;]]=],
        parameters = {"hardware", "bios", "systeminformation", "virtual machine", "vboxguest", "vmhgfs", "virtualbox", "vmware tools", "devicemap", "vbox__", "vbox"}
    },
    {
        command = [=[(?:^|\s+|"|'|\\)ping(\.(?:exe|py))[\s"':;]]=],
        parameters = {"127.0.0.1", "-n 1", "-n 301"}
    },
}

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

-- Функция анализа строки по регулярному выражению
local function analyze(cmd, object)
    local function is_contain(string, pattern_table, subelement)
        if type(pattern_table[subelement]) == "table" then
            if contains(pattern_table[subelement], string, "sub") then return true end
            
            return false
        end
        
        for _, pattern in ipairs(pattern_table) do
            if type(pattern[subelement]) == "table" then
                if contains(pattern[subelement], string, "sub") then return true end
            end
        end
        
        return false
    end

    local cmd_lower = cmd:lower()
    local object_lower = (object and object:lower()) or nil
    local is_command_parameter, is_cmdlet_parameter
    
    if object then
        if is_contain(cmd_lower, target_objects_patterns, "cmdlets") then
            is_cmdlet_parameter = is_contain(object_lower, target_objects_patterns, "parameters")
        end
    else
        for _, pattern in ipairs(command_line_patterns) do
            if cmd_lower:search(pattern.command) then
                is_command_parameter = is_contain(cmd_lower, pattern, "parameters")
                break
            end
        end
    end

    if is_cmdlet_parameter or is_command_parameter then return true end

    return false
end

-- Функция обработки логлайна
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")
    local is_vm, target_object, process_command, command_executed

    if compare(event_id, "==", "4103") then
        process_command = logline:gets("initiator.process.command")
        target_object = logline:gets("target.object.name")
        is_vm = analyze(process_command, target_object)
    elseif compare(event_id, "==", "4688") then
        command_executed = logline:gets("initiator.command.executed")
        target_object = command_executed:match("%.exe\"?%s*([%s%S]*)")
        is_vm = analyze(command_executed)
    end

    if is_vm then 
        if target_object then
            set_field_value(logline, "target.object.name", target_object)
        end
        
        set_field_value(logline, "event.rule.description", "vm detection")
        grouper1:feed(logline) 
    end
end

-- Функция группера #1
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local first_event = events[1]
    local commands = {}
    local cmdlets = {}
    local target_objects = {}

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local process_command = event:gets("initiator.process.command")

            if #process_command > 0 then
                table.insert(cmdlets, process_command)
                table.insert(target_objects, event:gets("target.object.name"))
            else
                local command_executed = event:gets("initiator.command.executed")
                table.insert(commands, command_executed)
            end
        end

        if (#commands + #cmdlets) > 3 then
            local meta = {
                user=first_event:gets("initiator.user.name"),
                command=string_cut(table.concat(commands, "; ")),
                commandlets=string_cut(table.concat(cmdlets, ";")),
                objects=string_cut(table.concat(target_objects, "; ")),               
                ip=first_event:gets("observer.host.ip"),
                hostname=first_event:gets("observer.host.hostname"),
                fqdn=first_event:gets("observer.host.fqdn"),
                risk=7.0,
                mitre={"T1497", "T1497.001", "T1497.003"},
                title="Подозрение на попытку определения выполнения ОС в среде виртуализации"
            }

            alert_function(events, meta)
            grouper1:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)