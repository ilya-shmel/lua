local template = [[
Подозрение на изменение процесса аутентификации.

ЦЕЛЕВОЙ УЗЕЛ:
IP: {{.Meta.observer_ip}}
Хост: {{.Meta.observer_hostname}}
FQDN: {{.Meta.observer_fqdn}}

ИНИЦИАТОР:
Пользователь: {{.Meta.user_name}}
UID: {{.Meta.user_id}}
Процесс: {{.Meta.process_path}}

КОМАНДА:
{{.Meta.command}}

ЗАТРОНУТЫЙ ФАЙЛ:
{{.Meta.target_file}}
]]

local detection_window = "5m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

local pam_files = {"/etc/pam.d/su", "/etc/pam.d/su-l", "/etc/pam.d/sshd", "/etc/pam.d/login",
                   "/etc/pam.d/common-auth", "/etc/pam.d/common-password", "/etc/pam.d/common-session",
                   "/etc/pam.d/system-auth", "/etc/pam.d/password-auth", "/etc/pam.d/sudo", "/etc/pam.d/gdm"}

local modification_commands = {"(?:sed|perl|awk|echo|cat|tee|vi|vim|nano|ed|ex|install|cp|mv)\\s+"}

local pam_module_patterns = {"pam_succeed_if.so", "pam_permit.so", "pam_unix.so", "pam_shadow.so",
                             "pam_deny.so", "pam_access.so", "pam_rootok.so", "pam_securetty.so",
                             "pam_cracklib.so", "pam_pwquality.so", "pam_google_authenticator.so"}

local function analyze(cmd)
    local cmd = cmd:lower()
    local is_pam_file = contains(pam_files, cmd, "sub")
    local is_pam_module = contains(pam_module_patterns, cmd, "sub")
    local is_modification = false
    
    for _, pattern in ipairs(modification_commands) do
        is_modification = cmd:search(pattern)
        
        if is_modification then
            break
        end
    end    
   
    if is_modification and (is_pam_file or pam_module) then
        return true
    end
        
    return false
end

function on_logline(logline)
    if logline:gets("observer.event.type") == "EXECVE" then
        if analyze(logline:gets("initiator.command.executed")) then
            grouper1:feed(logline)
        end
    else
        grouper1:feed(logline)
    end
end

function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    
    if unique_events > 1 then
        local log_exec = nil
        local log_sys = nil
        
        for _, log in ipairs(events) do
            if log:gets("observer.event.type") == "SYSCALL" then
                log_sys = log
            else
                log_exec = log
            end
        end

        if log_exec and log_sys then
            local command = log_exec:gets("initiator.command.executed")
            local target_file = command:match("/etc/pam%.d/[^%s]+")

            alert({
                template = template,
                meta = {
                    observer_ip = log_exec:gets("observer.host.ip", "IP-адрес не определён"),
                    observer_hostname = log_exec:gets("observer.host.hostname", "Имя узла не определено"),
                    observer_fqdn = log_exec:gets("observer.host.fqdn"),
                    user_name = log_sys:gets("initiator.user.name", "Имя пользователя не определено"),
                    user_id = log_sys:gets("initiator.user.id", "Идентификатор пользователя не определен"),
                    process_path = log_sys:gets("initiator.process.path.full", "Путь не определен"),
                    command = command,
                    target_file = target_file
                },
                risk_level = 9.0,
                asset_ip = log_exec:get_asset_data("observer.host.ip"),
                asset_hostname = log_exec:get_asset_data("observer.host.hostname"),
                asset_fqdn = log_exec:get_asset_data("observer.host.fqdn"),
                asset_mac = "",
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                logs = events,
                mitre = {"T1556.001", "T1556.003", "T1548.004"},
                trim_logs = 10
            })
            grouper1:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)