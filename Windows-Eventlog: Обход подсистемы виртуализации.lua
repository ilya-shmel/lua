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
Имя программы: {{ .Meta.program }}
Процесс/Путь к иcполняемому файлу: {{ .Meta.path }}
Родительский процесс: {{ .Meta.parent }}
]]

-- Параметры группера
local detection_window = "30s"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "event.rule.description"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"

-- Шаблоны и паттерны
local target_objects_patterns = {
    {   
        comandlets = {"Get-WmiObject", "Get-CimInstance"},   
        parameters = {"MSAcpi_ThermalZoneTemperature", "Class Win32_ComputerSystem", "Win32_ComputerSystem", "Win32_LogicalDisk", "Win32_Processor", "Win32_PhysicalMemory", "Win32_BIOS", "Win32_BaseBoard", "Win32_VideoController", "Win32_OperatingSystem", "Win32_Product", "Win32_NetworkAdapter", "Win32_SystemEnclosure", "Win32_SoundDevice", "Win32_DesktopMonitor", }
    },
    {
        comandlets = {"Get-Process"},
        parameters = {"vbox", "vmware", "vmtoolsd", "VBoxService", "vmwaretray", "vmacthlp", "vboxtray", "vmsrvc", "df5serv", "prl_tools"}
    },
    {
        comandlets = {"Test-Path"},
        parameters = {"vmsmb", "VBoxMiniRdrDN", "CdRom0"}
    },
     {
        comandlets = {"Get-Service"},
        parameters = {"vmtools", "vmdebug", "vmmouse", "VMMEMCTL", "vmhgfs", "VBoxGuest", "VBoxService", "VBoxSF", "VBoxMouse", "vmicheartbeat", "vmicvss", "vmicshutdown", "vmiexchange", "vmcompute", "hvhost", "vmsrvc"}
    }
}
local command_line_patterns = {
    {
        command = [=[[(?:^|\s+|"|'|\\)wmic[\s"':;][\s\w\/\\:'"]*get\s+]=],
        parameters = {"cpu", "memorychip", "bios", "baseboard", "nic", "virtualization", "VirtualSystemSettingData"}
    },
    {
        command = [=[(?:^|\s+|"|'|\\)tasklist\s*|\s*findstr[\s"':;]]=],
        parameters = {"vmms", "vmwp", "qemu-ga", "hyper-v", "vmtoolsd", "VBoxService"}
    },
    {
        command = [=[(?:^|\s+|"|'|\\)reg\s+query[\s"':;]]=],
        parameters = {"HARDWARE", "BIOS", "SystemInformation", "Virtual Machine", "VBoxGuest", "vmhgfs", "VirtualBox", "VMware Tools", "DEVICEMAP", "VBOX__", "VBOX"}
    }
}

-- Вспомогательная функция логирования значений в группере (удалить после тестирования на потоке)
local function log_grouper(events, events_number, unique_events, grouper_name, grouper_field)
    log("### " .. grouper_name .. " ###")
    log("Events: " ..#events.. ". Unique events: " ..unique_events)
    
    for _, event in ipairs(events) do
	    log("Event ID: " .. tostring(event:gets("observer.event.id")))
        log("Grouper field: " .. tostring(event:gets(grouper_field))) 
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
    if object then
        object_lower = object:lower()

        for _, pattern in ipairs(target_objects_patterns) do
            if contains(pattern.comandlets, cmd_lower) then
                if contains(pattern.parameters, object_lower) then return true
            end
        end
    else
        for _, pattern in ipairs(command_line_patterns) do
            if cmd_lower:search(pattern.command) then
                if cmd_lower:search(pattern.parameters) then return true
            end
        end
    end

    return false
end

-- Функция обработки логлайна
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")
    local is_vm
--    log_on_logline(logline)
    if compare(event_id, "==", "4103") then
        local process_command = logline:gets("initiator.process.command")
        local object_name = logline:gets("target.object.name")
        is_vm = analyze(process_command, object_name)
    elseif compare(event_id, "==", "4688") then
        local command_executed = logline:gets("initiator.command.executed")
        is_vm = analyze(command_executed, nil)
    end

    if is_vm then 
        set_field_value(logline, "event.rule.description", "vm detection")
        grouper1:feed(logline) 
    end
end

-- Функция группера #1
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_1, log_2
--    log_grouper(events, #events, unique_events, "on_grouped", grouped_by[4])
    if unique_events > 1 then
        for _, event in ipairs(events) do
            local parameter = event:gets("..."):lower()

            if syscall_name == "" then
                log_1 = event
            else
                log_2 = event
            end
        end

        if log_1 and log_2 then
            local meta = {
                user=first_event:gets("initiator.user.name"),
                command=string_cut(table.concat(commands, "; ")),
                path=first_event:gets("target.process.path.full"),
                program=first_event:gets("target.image.name"),
                parent=first_event:gets("initiator.process.parent.path.original"),
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
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)
