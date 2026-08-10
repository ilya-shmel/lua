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
Выполненные командлеты и параметры: {{ .Meta.objects }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "event.rule.description"}
local aggregated_by = {"target.object.name"}
local grouped_time_field = "@timestamp,RFC3339"

-- Шаблоны и паттерны
local target_objects_patterns = {
    {   
        comandlets = {"get-wmiobject", "get-ciminstance"},   
        parameters = {"msacpi_thermalzonetemperature", "class win32_computersystem", "win32_computersystem", "win32_logicaldisk", "win32_processor", "win32_physicalmemory", "win32_bios", "win32_baseboard", "win32_videocontroller", "win32_operatingsystem", "win32_product", "win32_networkadapter", "win32_systemenclosure", "win32_sounddevice", "win32_desktopmonitor", }
    },
    {
        comandlets = {"get-process"},
        parameters = {"vbox", "vmware", "vmtoolsd", "vboxservice", "vmwaretray", "vmacthlp", "vboxtray", "vmsrvc", "df5serv", "prl_tools"}
    },
    {
        comandlets = {"test-path"},
        parameters = {"vmsmb", "vboxminirdrdn", "cdrom0"}
    },
     {
        comandlets = {"get-service"},
        parameters = {"vmtools", "vmdebug", "vmmouse", "vmmemctl", "vmhgfs", "vboxguest", "vboxservice", "vboxsf", "vboxmouse", "vmicheartbeat", "vmicvss", "vmicshutdown", "vmiexchange", "vmcompute", "hvhost", "vmsrvc"}
    }
}
local command_line_patterns = {
    {
        command = [=[[(?:^|\s+|"|'|\\)wmic[\s"':;][\s\w\/\\:'"]*get\s+]=],
        parameters = {"cpu", "memorychip", "bios", "baseboard", "nic", "virtualization", "virtualsystemsettingdata"}
    },
    {
        command = [=[(?:^|\s+|"|'|\\)tasklist\s*|\s*findstr[\s"':;]]=],
        parameters = {"vmms", "vmwp", "qemu-ga", "hyper-v", "vmtoolsd", "vboxservice"}
    },
    {
        command = [=[(?:^|\s+|"|'|\\)reg\s+query[\s"':;]]=],
        parameters = {"hardware", "bios", "systeminformation", "virtual machine", "vboxguest", "vmhgfs", "virtualbox", "vmware tools", "devicemap", "vbox__", "vbox"}
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
    if #cmd > 128 then
        cmd = cmd:sub(1, 128).. "... "
    end

    return cmd
end

-- Функция анализа строки по регулярному выражению
local function analyze(cmd, object)
    local cmd_lower = cmd:lower()
    
    local debug_info = {
        {"Command: ", cmd},
        {"Object: ", object},
    }

    if object then
        local object_lower = object:lower()
        for _, pattern in ipairs(target_objects_patterns) do
            if contains(pattern.comandlets, cmd_lower) then
                table.insert(debug_info, {"Is comandlet: ", "true"})
                if contains(pattern.parameters, object_lower) then 
                    table.insert(debug_info, {"Is parameters: ", "true"})
                    return true 
                end
            end
        end
    else
        for _, pattern in ipairs(command_line_patterns) do
            if cmd_lower:search(pattern.command) then
                if contains(pattern.parameters, cmd_lower) then return true end
            end
        end
    end

    log_results("analyze", debug_info)

    return false
end

-- Функция обработки логлайна
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")
    local is_vm, target_object, process_command, object_name, command_executed

    if compare(event_id, "==", "4103") then
        process_command = logline:gets("initiator.process.command")
        object_name = logline:gets("target.object.name")
        is_vm = analyze(process_command, object_name)
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
        log("Send to grouper: " .. tostring(event_id))
        grouper1:feed(logline) 
    end

--    local debug_info = {
--        {"Event ID: ", event_id},
--        {"Is VM: ", is_vm},
--        {"Target object: ", target_object},
--        {"Process command: ", process_command},
--        {"Object name: ", object_name},
--        {"Command executed ", command_executed}        
--    }
--
--    log_results("on_logline", debug_info)
end

-- Функция группера #1
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local first_event = events[1]
    local commands = {}
    local objects = {}

    if unique_events > 1 then
        for _, event in ipairs(events) do
            local process_command = event:gets("initiator.process.command")
            
            if #process_command > 0 then
                table.insert(objects, {process_command, event:gets("target.object.name")})
            else
                local command_executed = event:gets("initiator.command.executed")
                table.insert(commands, command_executed)
            end
        end

        if (#commands + #objects) > 3 then
            local meta = {
                user=first_event:gets("initiator.user.name"),
                command=string_cut(table.concat(commands, "; ")),
                objects=string_cut(table.concat(objects, "; ")),               
                ip=first_event:gets("observer.host.ip"),
                hostname=first_event:gets("observer.host.hostname"),
                fqdn=first_event:gets("observer.host.fqdn"),
                risk=7.0,
                mitre={"T1497", "T1497.001"},
                title="Подозрение на попытку определения выполнения ОС в среде виртуализации"
            }

            alert_function(events, meta)
            grouper1:clear()
        end
    end

    local debug_info = {
        {"Events: ", #events },
        {"Unique events: ", unique_events},
        {"Number of commands: ", #commands},
        {"Number of comandlets: ", #objects}
    }

    log_results("on_grouped", debug_info)

end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)
