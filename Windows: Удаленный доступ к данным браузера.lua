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
local aggregated_by = {"observer.event.id"}
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
        pattern = "(?:get-(?:pnpdevice|ciminstance|WmiObject)(\\s+-(classname\\s+)?win32_usbcontrollerdevice)|usb(?:de|log)?view(\\.exe)?|devcon\\s+find\\s+usb|pnputil\\s+\\/enum-devices\\s+\\/class\\s+usb|reg\\s+query\\s+hklm\\\\system\\\\currentcontrolset\\\\enum\\\\usb|(?:ls)?usb(?:-t|ip)(\\\\s+list-remote)|lsblk|dmesg\\s+\\|\\s+grep\\s+usb)",
        mitre = {"T1120"}
    },
    
    -- HID устройства (клавиатуры, мыши)
    hid = {
        pattern = "(?:get-(?:pnpdevice|ciminstance|wmiobject)\\s+(-class\\s+(?:keyboard|mouse|hid))|win32_(?:keyboard|pointingdevice)|reg\\s+query\\s+hklm\\\\system\\\\currentcontrolset\\\\enum\\\\hid)",
        mitre = {"T1120"}
    },
    
    -- Принтеры и сканеры
    printer_scanner = {
        pattern = "(?:get-(?:printer|ciminstance|wmiobject)(\\s+win32_printer)?|wmic\\s+printer\\s+list\\s+brief|lp(?:stat|info)\\s+-[pv]|scanimage\\s+-l)",
        mitre = {"T1120"}
    },
    
    -- Камеры
    camera = {
        pattern = "(?:get-(?:pnpdevice|ciminstance)\\s+(?:-class\\s+image|win32_pnpentity\\s+\\|\\s+where%-object\\s+\\{[\\s\\S]*?camera)|reg\\s+query\\s+hklm\\\\system\\\\currentcontrolset\\\\enum\\\\usb\\s+\\|\\s+findstr\\s+camera|ls\\s+\\/dev\\/video|v4l2-ctl\\s+--list-devices)",
        mitre = {"T1120", "T1025"}
    },
    
    -- Bluetooth устройства
    bluetooth = {
        pattern = "(?:get-(?:pnpdevice|ciminstance|winuserlanguagelist|netadapter)\\s+(?:-class\\s+bluetooth|win32_pnpentity\\s+\\|\\s+where-object\\s+\\{[\\s\\S]*?bluetooth)|reg\\s+query\\s+hklm\\\\system\\\\currentcontrolset\\\\enum\\\\bth|bluetoothctl\\s+list|hcitool\\s+scan|rfkill\\s+list)",
        mitre = {"T1120"}
    },
    
    -- Диски и тома (T1539, T1025)
    disks_volumes = {
        pattern = "(?:get-(?:volume|disk|partition|physicaldisk|ciminstance|wmiobject)\\s+?(?:win32_logicaldisk)?|wmic\\s+logicaldisk\\s+list\\s+brief|fsutil\\s+fsinfo\\s+drives|mountvol|diskpart\\s+list\\s+volume|(ls)?blk(id)?|fdisk\\s+-l|df\\s+-h)",
        mitre = {"T1539", "T1025"}
    },
    
    -- Сетевые адаптеры
    network_adapters = {
        pattern = "(?:get-(?:netadapter|ciminstance|wmiobject)\\s+?(?:win32_networkadapter)?|wmic\\s+nic\\s+list\\s+brief|ipconfig\\s+\\/all|ifconfig\\s+-a|ip\\s+link\\s+show|lspci\\s+\\|\\s+grep\\s+ethernet)",
        mitre = {"T1120"}
    },
    
    -- Шина PCI (обнаружение всего подключенного)
    pci = {
        pattern = "(?:get-(?:pnpdevice|ciminstance)\\s+(?:-class\\s+pci|win32_pnpentity\\s+\\|\\s+where-object\\s+\\{[\\s\\S]*?PCI)|wmic\\s+path\\s+win32_pnpentity\\s+get\\s+deviceid\\s+\\|\\s+findstr\\s+pci|lspci(\\s+-v)?|dmidecode|ls\\s+\\/sys\\/bus\\/pci\\/devices)",
        mitre = {"T1120", "T1025"}
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
    
    for name, rule in ipairs(device_enumeration_patterns) do
        local is_enumeration = cmd:search(rule.pattern)
        if is_enumeration then
            table.insert(detected, name)
            for _, techique in ipairs(rule.mitre) do
--                log("Tech: " ..technique)
                techniques[technique] = true
            end
        end
    end
    
-- Дополнительная проверка по имени процесса (WMI/PowerShell)
    if image_name:lower():search("(?:wmic|powershell|cmd|cscript|wscript)") then
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
    local command_executed = logline:gets("initiator.command.executed")
    local target_image = logline:get("target.image.name") or logline:gets("initiator.process.image.name")
    
    local abuse_info = analyze(command_executed, target_image)

    if abuse_info then
-- Добавляем информацию о сработавших паттернах в logline
        local abuse_detected_patterns =  table.concat(abuse_info.detected, ", ")
        set_field_value(logline, "abuse.detected.patterns", abuse_detected_patterns)
        
        local techniques_list = {}
        for techique, _ in pairs(abuse_info.techniques) do
            table.insert(techniques_list, techique)
        end
        
        local techniques_table = table.concat(techniques_list, ",")
        set_field_value(logline, "abuse.techniques", techniques_table)
        
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local first_event = events[1]
    
    local initiator_name = first_event:get("initiator.user.name") or "Пользователь не определён"
    local host_ip = first_event:get("observer.host.ip") or first_event:get("reportchain.collector.host.ip")
    local host_name = first_event:get("observer.host.hostname") or "Имя узла не определено"
    local command_executed = first_event:gets("initiator.command.executed")
    local process_path = first_event:get("initiator.process.path.full") or first_event:get("initiator.process.path.name") or "Путь не определён"
    local detected_patterns = first_event:get("abuse.detected_patterns") or "Неизвестно"
    local techniques_str = first_event:get("abuse.techniques") or "T1120"
    
    -- Разбиваем техники на таблицу
    local mitre_techniques = {}
    for technique in ways(techniques_str, ",") do
        table.insert(mitre_techniques, technique)
    end
    
    if #command_executed > 128 then
        command_executed = command_executed:sub(1, 128).. "..."
    end
    
    -- Формируем имя для инцидента
    local incident_id = (host_name or "unknown") .. "_" .. (initiator_name or "unknown") .. "_device_enum"
    
    alert({
        template = template,
        meta = {
            user_name = initiator_name,
            command = command_executed,
            process = process_path,
            host_ip = host_ip,
            hostname = host_name,
            detected_patterns = detected_patterns
        },
        risk_level = 5.0,
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

-- Инициализация группера
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)