local_networks = storage.new("local-networks|Обнаружен высокий объем исходящего заблокированного трафика в сети")

local drops_treshold = 10

-- Шаблон алерта
local template = [[
	Подозрительно высокий объем исходящего заблокированного сетевого трафика.

    Узел-источник трафика: 
    IP - {{ .Meta.initiator_ip }}
    Hostname - {{ .Meta.initiator_hostname }}
    
    Узел-цель трафика:
    IP - {{ .Meta.target_ip }}
    Hostname - {{ .Meta.target_hostname }}
    Port - {{ .Meta.target_port }}
    
    Число заблокированных попыток: {{ .Meta.deny_counter }}
]]

-- Переменные для группера
local detection_window = "5m"
local grouped_by = {"initiator.host.ip", "initiator.host.hostname", "initiator.host.fqdn"}
local aggregated_by = {"target.host.ip", "target.socket.port"}
local grouped_time_field = "@timestamp,RFC3339"


-- Проверка на случай, если в событии вместо строки указано `[]`, или `{}`, или элемент принимает тип "Таблица"
local function check_empty_field(field)
    if field == "[]" or field == "{}" or field == "" or field:match("table:") then
        field = "Не определен"
        return field
    end
    
    return nil
end

local function get_unique_elements(input_array)
    local hash_table = {}    -- Временная таблица для отслеживания "увиденных" элементов
    local result_table = {}  -- Новый массив с уникальными значениями

    for _, element in ipairs(input_array) do
-- Если мы еще не встречали такое значение
        local is_odd = check_empty_field(element)
        if is_odd then
            element = is_odd
        end

        if not hash_table[tostring(element)] then
            table.insert(result_table, tostring(element)) -- Добавляем в результат
            hash_table[element] = true          -- Помечаем как "увиденное"
        end
    end

    return result_table
end

-- Функция конкатенации массива в строку
local function concat_function(ips_array)
    local all_elements = table.concat(ips_array, ", ")

    if #all_elements > 128 then
        all_elements = all_elements:sub(1,128).. "..."
    end
    
    return all_elements
end

-- Функция работы с логлайном
function on_logline(logline)
    local initiator_host_ip = logline:gets("initiator.host.ip")
    local target_host_ip = logline:gets("target.host.ip")
    local local_initiator = local_networks:search("ip", initiator_host_ip)
    local local_target = local_networks:search("ip", target_host_ip)
   
    
    if local_initiator then
       if local_target then
            return
       else
            grouper1:feed(logline)
       end
    end
end


-- Функция сработки группера
function on_grouped(grouped)
local events = grouped.aggregatedData.loglines
    if #events >= drops_treshold then
        local targets_ips = {}
        local target_hostnames = {}
        local target_ports = {}
        local all_targets_ips = ""
        local all_targets_hostnames = "" 

        for _, event in ipairs(events) do
            local target_ip = tostring(event:gets("target.host.ip"))
            local target_hostname = tostring(event:gets("target.host.hostname"))
            local target_port = tostring(event:gets("target.socket.port"))
            table.insert(targets_ips, tostring(target_ip))
            table.insert(target_hostnames, target_hostname)
            table.insert(target_ports,target_port)
        end
-- Оставляем уникальные значения
        initiator_ip = events[1]:get("initiator.host.ip") or events[1]:get("observer.host.ip")
        initiator_hostname = events[1]:gets("initiator.host.hostname")
        is_odd_field = check_empty_field(tostring(initiator_hostname))
        
        if is_odd_field then
            initiator_hostname = is_odd_field
        end

        targets_ips = get_unique_elements(targets_ips)
        target_hostnames = get_unique_elements(target_hostnames)
        target_ports = get_unique_elements(target_ports)
     
        all_targets_ips = concat_function(targets_ips)
        all_targets_hostnames = concat_function(target_hostnames)
        all_ports = concat_function(target_ports)

-- Функция алерта
        alert({
            template = template,
            meta = {
                initiator_ip=initiator_ip,
                initiator_hostname=initiator_hostname,
                target_ip=all_targets_ips,
                target_hostname=all_targets_hostnames,
                target_port=all_ports,
                deny_counter=#events
                },
            risk_level = 6.0, 
            asset_ip = events[1]:get_asset_data("observer.host.ip"),
            asset_hostname = events[1]:get_asset_data("observer.host.hostname"),
            asset_fqdn = events[1]:get_asset_data("observer.host.fqdn"),
            asset_mac = events[1]:get_asset_data(""),
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "",
            logs = events,
            mitre = {"T1498", "T1498.001"},
            trim_logs = 10
            }
        )
        grouper1:clear()
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)