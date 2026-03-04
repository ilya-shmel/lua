-- Linux: Отключение подсистемы аудита

local detection_window = "1m"
local create_incident = true
local assign_to_customer = false
local grouped_time_field = "@timestamp,RFC3339"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}

local template = [[
Обнаружена попытка отключения подсистемы аудита.

Узел:
{{ if .First.observer.host.ip }}IP - {{ .First.observer.host.ip }}{{ else }}"IP-адрес неопределен"{{ end }}
{{ if .First.observer.host.hostname }}Hostname - {{ .First.observer.host.hostname }}{{ else }}"Имя узла неопределено"{{ end }}

Пользователь(инициатор): {{ .Meta.user_name }}
Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
Выполненная команда: {{ .Meta.command }}
]]

prefix = "(?:^|\\s+|\\\\|\\/|\"|\')"
-- Паттерн для команд отключения аудита
local audit_disable_pattern = prefix.. "(?:systemctl\\s+(?:stop|disable|mask)\\s+(auditd|journald)|service\\s+auditd\\s+stop|\\/etc\\/init\\.d\\/auditd\\s+stop|auditctl\\s+-e\\s+0|auditctl\\s+--enable\\s+0|pkill\\s+auditd|kill(?:all)?\\s+(?:-9\\s+)?auditd|sed\\s+-i\\s+s\\/[^\\/]+\\/storage=none\\/\\s+(\\/[^\\/]*)+\\/journal(d)?\\.conf)"

-- Паттерн для выгрузки модуля аудита ядра
local module_unload_pattern = prefix..  "(?:rmmod\\s+audit|modprobe\\s+-r\\s+audit)"

-- Паттерн для исключений (легитимные операции с аудитом)
local exclude_pattern = prefix.. "(?:systemctl\\s+(?:start|restart|reload|enable|status)\\s+(auditd|journald)|service\\s+auditd\\s+(?:start|restart|status)|\\/etc\\/init\\.d\\/auditd\\s+(?:start|restart)|auditctl\\s+-e\\s+1|auditctl\\s+--enable\\s+1|auditctl\\s+-s|auditctl\\s+--status|modprobe\\s+audit|lsmod\\s+.*audit)"

local function is_audit_disable_command(command)
    command = command:lower()
    return command:search(audit_disable_pattern) or command:search(module_unload_pattern)
end

function on_logline(logline)

    local event_type = logline:gets("observer.event.type")

    if event_type == "EXECVE" or event_type == "PROCTITLE" then
        local command = logline:gets("initiator.command.executed")
        if command and #command and is_audit_disable_command(command) and not command:search(exclude_pattern) then
            grouper1:feed(logline)
        end
        
    elseif event_type == "SYSCALL" then
        grouper1:feed(logline)
    end
end

function on_grouped(grouped)
    if grouped.aggregatedData.unique.total > 1 then

        local log_sys = nil
        local log_exec = nil
        
        -- Разделяем события по типам
        for _, event in ipairs(grouped.aggregatedData.loglines) do
            local etype = event:gets("observer.event.type")
            if etype == "SYSCALL" then
                log_sys = event
            elseif etype == "EXECVE" or etype == "PROCTITLE" then
                log_exec = event
            end
        end
        
        if log_exec and log_sys then   
            alert({
                template = template,
                risk_level = 8.0,
                asset_ip = log_exec:get_asset_data("observer.host.ip"),
                asset_hostname = log_exec:get_asset_data("observer.host.hostname"),
                asset_fqdn = log_exec:get_asset_data("observer.host.fqdn"),
                create_incident = create_incident,
                assign_to_customer = assign_to_customer,
                logs = grouped.aggregatedData.loglines,
                trim_logs = 15,
                meta = {
                    user_name = log_sys:gets("initiator.user.name", "Не определен"),
                    command = log_exec:gets("initiator.command.executed"),
                    command_path = log_sys:gets("initiator.process.path.full", "Не определен"),
                }, 
                mitre = {"T1562", "T1562.001", "T1070"}
            })
            grouper1:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)