-- Шаблоны алерта
local template = [[
Подозрение на динамический обмен данными (DDE) с помощью ПО из пакета MS Office.

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{ or .Meta.ip "IP-адрес не определён" }}
Узел: {{ or .Meta.hostname "Имя узла не определено" }}
FQDN: {{ or .Meta.fqdn "FQDN узла не определено" }}

ИНИЦИАТОР:
Пользователь: {{ or .Meta.user_name "Пользователь не поределён" }}
Путь инициатора : {{ .Meta.initiator_path }}
Целевой путь: {{ .Meta.target_path }}

ВЫПОЛНЕННАЯ КОМАНДА:
Команда-инициатор: {{ .Meta.initiator_command }}
Целевая команда: {{ .Meta.target_command }}
Скрытая команда: {{ .Meta.final_command }}
]]

-- Переменные для группера
local detection_window = "30s"
local grouped_time_field = "@timestamp,RFC3339"

local grouped_by1 = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "event.process.id"}
local aggregated_by1 = {"observer.event.id"} 

local grouped_by2 = {"observer.host.ip", "observer.host.hostname", "observer.host.fqdn", "initiator.process.parent.id"}
local aggregated_by2 = {"operation.type"} 

-- Регулярные выражения
--local prefix = "(?:^|\\/|\\s+|\"|\'|\\\\)" 
local command_patterns = {
        ["cmd_execution"] = "(-\\w+(\\s+[^-\\s]+)?\\s*)+\\s+(?:\"|\')[\\s\\S]*(?:\"|\')",
        ["office_root"] = "\\s+\\/n\\s+(?:\'|\")(([^\\\\]+\\\\)+)?\\w+\\.(?:do|xl|p[po])(?:[sta]|[ct])[mx]?(?:\'|\")\\s+\\/o",
        ["posh_execution"] = "(?:ps1|psm|vba|bat)(?:\"|\')\\)?;\\s+(?:invoke-expression|iex)\\s+[\\s\\S]*"
}
local shell_commands = { "powershell.exe", "cmd.exe", "pwsh.exe" }

local function string_cut(cmd)
    if #cmd > 128 then
        cmd = cmd:sub(1, 128).. "... "
    end

    return cmd
end


-- Функция анализа строки
local function analyze(cmd, pattern)
    
    if cmd:search(pattern) then return true end
    
    return false
end

-- Функция работы с логлайном
function on_logline(logline)
    local event_id = logline:gets("observer.event.id")
    local command_executed = logline:gets("initiator.command.executed"):lower()

    if compare(event_id, "==", "4688") then
        local target_image = logline:gets("target.image.name"):lower()

        if contains(shell_commands, target_image, "sub") then
            if analyze(command_executed, command_patterns["cmd_execution"]) then
                local target_id = tonumber(logline:gets("target.process.id"):gsub("^0[xX]", ""), 16) -- initiator.process.parent.id
                set_field_value(logline, "event.process.id", target_id)
                set_field_value(logline, "operation.type", "cmd_execution")
                grouper1:feed(logline)
            end
        else
            if analyze(command_executed, command_patterns["office_root"]) then
                local target_id = tonumber(logline:gets("target.process.id"):gsub("^0[xX]", ""), 16)
                set_field_value(logline, "initiator.process.parent.id", target_id)
                set_field_value(logline, "operation.type", "office_root")
                grouper2:feed(logline)
            end
        end
    elseif compare(event_id, "==", "4104") then
        if analyze(command_executed, command_patterns["posh_execution"]) then
            local observer_id = logline:gets("observer.process.id")
            set_field_value(logline, "event.process.id", observer_id)
            set_field_value(logline, "operation.type", "posh_execution")
            grouper1:feed(logline)
        end
    end
end

-- Функция сработки группера #1
function on_grouped1(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_cmd_exec, log_scriptblock

    if unique_events > 1 then
        for _, event in ipairs(events) do
            if event:gets("operation.type") == "cmd_execution" then
                log_cmd_exec = event
            else
                log_scriptblock = event
            end
        end

        if log_cmd_exec and log_scriptblock then
            local parent_id = tonumber(log_cmd_exec:gets("initiator.process.parent.id"):gsub("^0[xX]", ""), 16) 
            set_field_value(log_cmd_exec, "initiator.process.parent.id", parent_id)
            set_field_value(log_scriptblock, "initiator.process.parent.id", parent_id)
            grouper2:feed(log_cmd_exec)
            grouper2:feed(log_scriptblock)
            grouper2:clear()
        end
    end
end

-- Функция сработки группера #2
function on_grouped2(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local log_cmd_exec, log_office_root, log_scriptblock
    local all_commands = {}

    if unique_events > 2 then
        for _, event in ipairs(events) do
                local event_id= event:gets("observer.event.id")
                local operation_type = event:gets("operation.type")

                if operation_type == "posh_execution" then
                    log_scriptblock = event
                elseif operation_type == "cmd_execution" then
                    log_cmd_exec = event
                else
                    log_office_root = event
                end 
        end

        if log_cmd_exec and log_office_root and log_scriptblock then
            local initiator_name = log_cmd_exec:gets("initiator.user.name")  
            local host_ip = log_cmd_exec:get("observer.host.ip")
            local host_name = log_cmd_exec:gets("observer.host.hostname")
            local host_fqdn = log_cmd_exec:gets("observer.host.fqdn")
            local initiator_command = string_cut(log_office_root:gets("initiator.command.executed"))
            local target_command = string_cut(log_cmd_exec:gets("initiator.command.executed"))
            local final_command = string_cut(log_scriptblock:gets("initiator.command.executed"))
            local initiator_path = log_office_root:gets("initiator.process.parent.path.original")
            local target_path = log_office_root:gets("target.process.path.full")
            
            alert({
               template = template,
               meta = {
                   user_name=initiator_name,
                   initiator_command=initiator_command,
                   target_command=target_command,
                   final_command=final_command,
                   initiator_path=initiator_path,
                   target_path=target_path,
                   ip=host_ip,
                   hostname=host_name,
                   fqdn=host_fqdn
                   },
               risk_level = 6.0, 
               asset_ip = host_ip,
               asset_hostname = host_name,
               asset_fqdn = host_fqdn,
               asset_mac = "",
               create_incident = true,
               incident_group = "",
               assign_to_customer = false,
               incident_identifier = "",
               logs = events,
               mitre = {"T1559.002"},
               trim_logs = 10
               }
            )
            grouper2:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by1, aggregated_by1, grouped_time_field, detection_window, on_grouped1)
grouper2 = grouper.new(grouped_by2, aggregated_by2, grouped_time_field, detection_window, on_grouped2)