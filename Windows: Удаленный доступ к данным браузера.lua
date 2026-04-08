-- Шаблон алерта
local template = [[
Подозрение на попытку разведки подключённых периферийных устройств.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{.Meta.command}}
Обнаруженные признаки: {{ .Meta.detected_patterns }}
]]

-- Параметры группера
local detection_window = "2m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "initiator.user.id"}
local aggregated_by = {}
local grouped_time_field = "@timestamp,RFC3339"

-- Белый список (исключения)
local whitelist_patterns = {
    "company[-_]approved",
    "it[-_]support",
    "allowlist",
    "whitelist"
}

-- Регулярные выражения для обнаружения разведки устройств
local device_enumeration_patterns = {
    -- USB устройства (T1120)
    usb = {
        pattern = "(?i)(?:Get%-PnpDevice|Get%-CimInstance\\s+-ClassName\\s+Win32_USBControllerDevice|Get%-WmiObject\\s+Win32_USBControllerDevice|usbview\\.exe|USBDeview|USBLogView|DevCon\\s+find\\s+USB|pnputil\\s+/enum%-devices\\s+/class\\s+USB|reg\\s+query\\s+HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Enum\\\\USB|lsusb|lsusb%-t|usbip\\s+list%-remote|lsblk|dmesg\\s+\\|\\s+grep\\s+usb)",
        techniques = {"T1120"}
    },
    
    -- HID устройства (клавиатуры, мыши)
    hid = {
        pattern = "(?i)(?:Get%-PnpDevice\\s+-Class\\s+(?:Keyboard|Mouse|HID)|Get%-CimInstance\\s+Win32_Keyboard|Get%-WmiObject\\s+Win32_PointingDevice|Get%-CimInstance\\s+Win32_PointingDevice|reg\\s+query\\s+HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Enum\\\\HID)",
        techniques = {"T1120"}
    },
    
    -- Принтеры и сканеры
    printer_scanner = {
        pattern = "(?i)(?:Get%-Printer|Get%-CimInstance\\s+Win32_Printer|Get%-WmiObject\\s+Win32_Printer|wmic\\s+printer\\s+list\\s+brief|lpstat\\s+-p|lpinfo\\s+-v|scanimage\\s+%-L)",
        techniques = {"T1120"}
    },
    
    -- Камеры
    camera = {
        pattern = "(?i)(?:Get%-PnpDevice\\s+-Class\\s+Image|Get%-CimInstance\\s+Win32_PnPEntity\\s+\\|\\s+Where%-Object\\s+\\{.*Camera|reg\\s+query\\s+HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Enum\\\\USB\\s+\\|\\s+findstr\\s+[Cc]amera|ls\\s+/dev/video|v4l2%-ctl\\s+%-%-list%-devices)",
        techniques = {"T1120", "T1025"}
    },
    
    -- Bluetooth устройства
    bluetooth = {
        pattern = "(?i)(?:Get%-PnpDevice\\s+-Class\\s+Bluetooth|Get%-CimInstance\\s+Win32_PnPEntity\\s+\\|\\s+Where%-Object\\s+\\{.*Bluetooth|Get%-WinUserLanguageList|Get%-NetAdapter\\s+\\|\\s+Where%-Object\\s+\\{.*Bluetooth|reg\\s+query\\s+HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Enum\\\\BTH|bluetoothctl\\s+list|hcitool\\s+scan|rfkill\\s+list)",
        techniques = {"T1120"}
    },
    
    -- Диски и тома (T1539, T1025)
    disks_volumes = {
        pattern = "(?i)(?:Get%-Volume|Get%-Disk|Get%-Partition|Get%-PhysicalDisk|Get%-CimInstance\\s+Win32_LogicalDisk|Get%-WmiObject\\s+Win32_LogicalDisk|wmic\\s+logicaldisk\\s+list\\s+brief|fsutil\\s+fsinfo\\s+drives|mountvol|diskpart\\s+list\\s+volume|lsblk|fdisk\\s+%-l|df\\s+%-h|blkid)",
        techniques = {"T1539", "T1025"}
    },
    
    -- Сетевые адаптеры
    network_adapters = {
        pattern = "(?i)(?:Get%-NetAdapter|Get%-CimInstance\\s+Win32_NetworkAdapter|Get%-WmiObject\\s+Win32_NetworkAdapter|wmic\\s+nic\\s+list\\s+brief|ipconfig\\s+/all|ifconfig\\s+%-a|ip\\s+link\\s+show|lspci\\s+\\|\\s+grep\\s+[Ee]thernet)",
        techniques = {"T1120"}
    },
    
    -- Шина PCI (обнаружение всего подключенного)
    pci = {
        pattern = "(?i)(?:Get%-PnpDevice\\s+-Class\\s+PCI|Get%-CimInstance\\s+Win32_PnPEntity\\s+\\|\\s+Where%-Object\\s+\\{.*PCI|wmic\\s+path\\s+Win32_PnPEntity\\s+get\\s+DeviceID\\s+\\|\\s+findstr\\s+PCI|lspci|lspci\\s+-v|dmidecode|ls\\s+/sys/bus/pci/devices)",
        techniques = {"T1120", "T1025"}
    }
}

-- Проверка на белый список
local function is_whitelisted(cmd)
    cmd = cmd:lower()
    for _, pattern in ipairs(whitelist_patterns) do
        if cmd:search(pattern) then
            return true
        end
    end
    return false
end

-- Анализ команды на наличие признаков разведки устройств
local function analyze_device_enumeration(cmd, image_name)
    cmd = cmd:lower()
    local detected = {}
    local techniques = {}
    
    for name, rule in pairs(device_enumeration_patterns) do
        if cmd:search(rule.pattern) then
            table.insert(detected, name)
            for _, tech in ipairs(rule.techniques) do
                techniques[tech] = true
            end
        end
    end
    
    -- Дополнительная проверка по имени процесса (WMI/PowerShell)
    if image_name and image_name:lower():search("(?:wmic|powershell|cmd|cscript|wscript)") then
        -- Если процесс подозрительный, но паттерны не сработали, проверяем специфичные флаги
        if cmd:search("(?:list|enum|get|query)\\s+(?:device|pnp|usb|drive|volume|adapter)") then
            table.insert(detected, "generic_enumeration")
            techniques["T1120"] = true
        end
    end
    
    return detected, techniques
end

-- Основная функция анализа
local function analyze(cmd, image_name)
    -- Проверка белого списка
    if is_whitelisted(cmd) then
        return false
    end
    
    local detected, techniques = analyze_device_enumeration(cmd, image_name)
    
    if #detected > 0 then
        return {detected = detected, techniques = techniques}
    end
    
    return false
end

-- Функция работы с логлайном
function on_logline(logline)
    local command_executed = logline:gets("initiator.command.executed") or ""
    local target_image = logline:get("target.image.name") or logline:get("initiator.process.image.name") or ""
    
    -- Если нет команды и нет образа процесса — выходим
    if command_executed == "" and target_image == "" then
        return
    end
    
    local abuse_info = analyze(command_executed, target_image)
    
    if abuse_info then
        -- Добавляем информацию о сработавших паттернах в logline
        logline:set_field("abuse.detected_patterns", table.concat(abuse_info.detected, ", "))
        
        local techniques_list = {}
        for tech, _ in pairs(abuse_info.techniques) do
            table.insert(techniques_list, tech)
        end
        logline:set_field("abuse.techniques", table.concat(techniques_list, ","))
        
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    if not grouped.aggregatedData.loglines or #grouped.aggregatedData.loglines == 0 then
        return
    end
    
    local events = grouped.aggregatedData.loglines
    local first_event = events[1]
    
    local initiator_name = first_event:get("initiator.user.name") or "Пользователь не определён"
    local host_ip = first_event:get_asset_data("observer.host.ip") or first_event:get("observer.host.ip")
    local host_name = first_event:get_asset_data("observer.host.hostname") or first_event:get("observer.host.hostname")
    local command_executed = first_event:gets("initiator.command.executed") or ""
    local process_path = first_event:get("initiator.process.path.full") or first_event:get("initiator.process.path.name") or "Путь не определён"
    local detected_patterns = first_event:get("abuse.detected_patterns") or "Неизвестно"
    local techniques_str = first_event:get("abuse.techniques") or "T1120"
    
    -- Разбиваем техники на таблицу
    local mitre_techniques = {}
    for tech in ways(techniques_str, ",") do
        table.insert(mitre_techniques, tech)
    end
    
    if #command_executed > 256 then
        command_executed = command_executed:sub(1, 256) .. "..."
    end
    
    -- Формируем имя для инцидента
    local incident_id = (host_name or "unknown") .. "_" .. (initiator_name or "unknown") .. "_device_enum"
    
    alert({
        template = template,
        meta = {
            user_name = initiator_name,
            command = command_executed,
            process = process_path,
            host_ip = host_ip or "",
            hostname = host_name or "",
            detected_patterns = detected_patterns
        },
        risk_level = 6.5,
        asset_ip = host_ip or "",
        asset_hostname = host_name or "",
        asset_fqdn = first_event:get_asset_data("observer.host.fqdn") or "",
        asset_mac = "",
        create_incident = true,
        incident_group = "Device Enumeration",
        assign_to_customer = false,
        incident_identifier = incident_id,
        logs = events,
        mitre = mitre_techniques,
        trim_logs = 10
    })
    
    grouper1:clear()
end

-- Вспомогательная функция для разбиения строки (если нужна)
function ways(str, delim)
    if not str then return {} end
    local result = {}
    for match in (str .. delim):gmatch("(.-)" .. delim) do
        table.insert(result, match)
    end
    return result
end

-- Инициализация группера
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)