local template = [[
Обнаружено извлечение информации о shell-оболочках системы.

Узел:
{{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
{{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}

Пользователь(инициатор): {{ .Meta.user_name }}
Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
Тип операции: {{ .Meta.operation_type }}
Выполненная команда: {{ .Meta.command }}
]]

local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

local shell_patterns =
    "(?i)(?:^|\\\\|/|\\s+|\"|'|\\n)((?:cat|grep|head|tail|less|more|sed|awk|strings)\\s+.*/etc/shells|(?:getent|grep|cut)\\s+(shell|passwd)|chsh\\s+-l|ps\\s+-p\\s+\\$\\$)"

local false_positive_patterns = {"run-parts.*cron\\.(hourly|daily|weekly|monthly)", "cd\\s+/\\s+&&\\s+run-parts",
                                 "/etc/cron\\.", "systemd.*cron", "anacron", "/usr/lib/update-notifier",
                                 "apt-get.*update", "dpkg.*configure", "yum.*update", "/usr/bin/unattended-upgrade"}

local pattern_cat_shells = "(?i)(?:^|/|\"|'|\\s+)(cat)\\s+.*/etc/shells"
local pattern_grep_shells = "(?i)(?:^|/|\"|'|\\s+)(grep)\\s+.*/etc/shells"
local pattern_getent_shells = "(?i)(?:^|/|\"|'|\\s+)(getent)\\s+(?:shell|passwd)"
local pattern_which_shell = "(?i)(?:^|/|\"|'|\\s+)(?:which|whereis)\\s+(?:bash|sh|zsh|ksh|tcsh)"
local pattern_shell_env = "(?i)(?:^|/|\"|'|\\s+)(?:echo|printf).*\\$(?:shell|0)"
local pattern_chsh = "(?i)(?:^|/|\"|'|\\s+)(chsh)\\s+-l"
local pattern_ps_shell = "(?i)(?:^|/|\"|'|\\s+)(ps)\\s+-p\\s+\\$\\$"

local function extract_operation_type(cmd)
    if cmd:search(pattern_cat_shells) then
        return "Чтение /etc/shells через cat"
    elseif cmd:search(pattern_grep_shells) then
        return "Поиск в /etc/shells через grep"
    elseif cmd:search(pattern_getent_shells) then
        return "Получение информации shell через getent"
    elseif cmd:search(pattern_which_shell) then
        return "Определение местоположения shell (which/whereis)"
    elseif cmd:search(pattern_shell_env) then
        return "Вывод переменной окружения SHELL"
    elseif cmd:search(pattern_chsh) then
        return "Просмотр доступных shell (chsh -l)"
    elseif cmd:search(pattern_ps_shell) then
        return "Определение текущего shell через ps"
    else
        return "Операция с информацией о shell"
    end
end

local function is_false_positive(cmd, parent_path)
    for _, pattern in ipairs(false_positive_patterns) do
        if cmd:search(pattern) then
            return true
        end
    end

    if parent_path then
        for _, pattern in ipairs(false_positive_patterns) do
            if parent_path:search(pattern) then
                return true
            end
        end
    end

    return false
end

local function analyze(cmd)
    local regular = cmd:lower():search(shell_patterns)
    if regular then
        return true
    end

    return false
end

function on_logline(logline)
    local event_type = logline:gets("observer.event.type")

    if event_type == "EXECVE" or event_type == "PROCTITLE" then
        local command = logline:gets("initiator.command.executed")
        local parent_path = logline:gets("initiator.process.parent.path.full")

        if command and command ~= "" and analyze(command) then
            if not is_false_positive(command, parent_path) then
                grouper1:feed(logline)
            end
        end
    elseif event_type == "SYSCALL" then
        grouper1:feed(logline)
    end
end

function on_grouped(grouped)
    if grouped.aggregatedData.unique.total > 1 then
        local log_sys = nil
        local log_exec = nil

        for _, event in ipairs(grouped.aggregatedData.loglines) do
            local etype = event:gets("observer.event.type")
            if etype == "SYSCALL" then
                log_sys = event
            else
                log_exec = event
            end
        end

        if log_exec and log_sys then
            local command = log_exec:gets("initiator.command.executed")
            local parent_path = log_sys:gets("initiator.process.parent.path.full")

            if not is_false_positive(command, parent_path) then
                alert({
                    template = template,
                    meta = {
                        user_name = log_sys:gets("initiator.user.name", "Не определен"),
                        command = command,
                        command_path = log_sys:gets("initiator.process.path.full", "Не определен"),
                        operation_type = extract_operation_type(command)
                    },
                    risk_level = 4.5,
                    asset_ip = log_exec:get_asset_data("observer.host.ip"),
                    asset_hostname = log_exec:get_asset_data("observer.host.hostname"),
                    asset_fqdn = log_exec:get_asset_data("observer.host.fqdn"),
                    asset_mac = "",
                    create_incident = true,
                    incident_group = "",
                    assign_to_customer = false,
                    incident_identifier = "",
                    logs = grouped.aggregatedData.loglines,
                    mitre = {"T1082", "T1518"},
                    trim_logs = 10
                })
            end
            grouper1:clear()
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)