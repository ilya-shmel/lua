-- Linux: Создание скрытых файловых папок и в них исполняемых скриптов
local template = [[
     Обнаружено cоздание скрытых файловых папок и в них исполняемых скриптов.
    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Файл: {{.Meta.file_name}}
    Окружение, из которого выполнялась команда: {{ .Meta.path }}
    Выполненная команда: {{ .Meta.command }}
]]


local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn"}
local aggregated_by = {"observer.event.id"}
local grouped_time_field = "@timestamp,RFC3339"


-- Регулярное выражение
local dir_pattern = "(?:^|~?\\/)(\\.[^\\/]+)(?:\\/|$)"
local file_pattern = "\\.[^\\/]+\\/[^\\/]+\\.(?:(?:ba|z|k|c)?sh|py|pl|rb|php|js|lua|ps1|awk|sed|tcl|groovy|command|run|bin)(\\.sw(?:p|x))?"

-- Функция анализа строк
local function analyze(cmd,pattern)
    local cmd_lower = cmd:lower()
    local is_regular = cmd_lower:search(pattern)   
    if is_regular then
        return is_regular
    end
end

-- Функция обработки логлайна  
function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    local target_type = logline:gets("target.object.type")
    local syscall_name = logline:gets("target.syscall.name")

-- Создание файлов или директорий
    if event_type == "PATH" and target_type == "parent" or target_type == "create" or target_type == "normal" then
       grouper1:feed(logline)
    end    

-- Добавление права исполнения
    if event_type == "SYSCALL" and syscall_name == "fchmodat" or syscall_name == "fchmod" then
        local target_permissions = logline:gets("target.permissions.granted.original")
        local convert_to_octal
-- если строка начинается с "0" и содержит только 0..7 → это octal        
        if target_permissions:match("^0[0-7]+$") then
            convert_to_octal = tonumber(target_permissions, 8) or 0
-- если содержит только hex‑символы → парсим как hex
        elseif target_permissions:match("^[0-9a-fA-F]+$") then
            convert_to_octal = tonumber(target_permissions, 16) or 0       
-- иначе пробуем как decimal
        else
            convert_to_octal = tonumber(target_permissions, 10) or 0
        end
    
-- извлекаем три октальных цифры прав: owner, group, other
        local owner = math.floor(convert_to_octal / 64) % 8
        local group = math.floor(convert_to_octal / 8)  % 8
        local other = convert_to_octal % 8
        
        if owner == 7 or group == 7 or other == 7 then
            grouper1:feed(logline)
        end
    end
end

-- Функция группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_path_parent = {}
    local log_path_created = {}
    local log_path_normal = ""
    local log_syscall = {}
    local hidden_dirname = nil
    local script_name = {}
    
    if unique_events > 1 then
        
        for _, event in ipairs(events) do
            local event_type = event:gets("observer.event.type")
            local target_type = event:gets("target.object.type")
            if event_type == "SYSCALL" then
                table.insert(log_syscall, event)
            elseif event_type == "PATH" and target_type == "normal" then
                log_path_normal = event
            elseif event_type == "PATH" and target_type == "parent" then
                table.insert(log_path_parent, event)
            elseif event_type == "PATH" and target_type == "create" then
                table.insert(log_path_created, event)    
            end
        end
        script_name[1] = log_path_normal:gets(("target.object.path.full"))

        for _, created_event in ipairs(log_path_created) do 
            local original_permissions = created_event:gets("target.permissions.granted.original") or ""
          
            if #original_permissions >= 2 then
                local file_bits = original_permissions:match("^..")
               
                if file_bits == "01" then
                    script_name[2] = created_event:gets(("target.object.path.full"))
                end
            end
        end

        for _, parent_event in ipairs(log_path_parent) do 
                      
            if #tostring(log_path_parent[1]) > #tostring(log_path_parent[2]) then
                hidden_dir = log_path_parent[1]
            else 
                hidden_dir = log_path_parent[2]
            end
        end
    end


        if script_name[1] == script_name[2] then
            local command_executed = log_syscall[1]:gets("initiator.process.path.name")
            local command_path = log_syscall[1]:gets("initiator.process.path.full")
            local initiator_name = log_syscall[1]:gets("initiator.user.name")
            local hidden_dirname = hidden_dir:gets("target.object.path.full")
            local file_name = script_name[1]
            file_name = hidden_dirname.. "/" ..file_name
            local host_ip = log_syscall[1]:gets("observer.host.ip") 
            local host_name = log_syscall[1]:gets("observer.host.hostname")
            local host_fqdn = log_syscall[1]:gets("observer.host.fqdn")

            alert({
                template = template,
                meta = {
                    user_name = initiator_name,
                    command = command_executed,
                    path = command_path,
                    file_name = file_name
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
                mitre = {"T1564.001", "T1059"},
                trim_logs = 10
            })
            grouper1:clear()   
        end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)