-- Шаблоны алерта
local template = [[
	Обнаружены ошибки NTFS.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Путь к файлу: {{ .Meta.path }}
    Код ошибки: {{ if .First.event.error.code }}{{ .First.event.error.code }}{{ else }}"Код ошибки неопределен"{{ end }}
    Описание ошибки: {{ if .First.event.description }}{{ .First.event.description }}{{ else }}"Ошибка файловой системы"{{ end }}
]]

-- Переменные для группера
local detection_window = "5m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Функция выборки уникальных значений в массиве
local function get_unique_elements(input_array)
    local hash_table = {}    
    local result_table = {}  
    
    for _, element in ipairs(input_array) do
        if not hash_table[tostring(element)] then
            table.insert(result_table, tostring(element)) 
            hash_table[element] = true          
        end
    end

    return result_table
end

-- Функция работы с логлайном
function on_logline(logline)
    grouper1:feed(logline)
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local file_path = {}
    
    if unique_events > 1 or #events > 4 then
        for _, event in ipairs(events) do
            local error_path = event:gets("target.file.path")
            table.insert(file_path, error_path)
        end
       
        file_path = get_unique_elements(file_path)
        local all_paths = table.concat(file_path, "; ")
        local host_ip = events[1]:get_asset_data("observer.host.ip")
        local host_name = events[1]:get_asset_data("observer.host.hostname")
        local host_fqdn = events[1]:get_asset_data("observer.host.fqdn")
                
        alert({
            template = template,
            meta = {
                path=all_paths
                },
            risk_level = 8.0, 
            asset_ip = host_ip,
            asset_hostname = host_name,
            asset_fqdn = host_fqdn,
            asset_mac = "",
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "",
            logs = events,
            mitre = {"T1561"},
            trim_logs = 10
            }
        )
        grouper1:clear()
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)