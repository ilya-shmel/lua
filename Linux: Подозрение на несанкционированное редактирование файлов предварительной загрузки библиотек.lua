-- Linux: Подозрение на несанкционированное редактирование файлов предварительной загрузки библиотек

local template = [[
Обнаружено редактирование файлов предварительной загрузки библиотек (LD_PRELOAD persistence).

Узел:
{{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}Не определен{{ end }}
{{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}Не определен{{ end }}

Пользователь(инициатор): {{ .Meta.user_name }}
Выполненная команда: {{ .Meta.command }}
Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]

local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname","observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"


local ld_preload_pattern = "(?i)(?:/etc/ld\\.so(?:\\.preload|\\.conf|$)|LD_PRELOAD|LD_LIBRARY_PATH|ldconfig)"

-- Функция очистки null bytes
local function clean(cmd)
    local c = string.gsub(cmd, "%z", " ")
    c = string.gsub(c, "%s+", " ")
    return string.match(c, "^%s*(.-)%s*$") or c
end

-- Единая функция анализа (через search)
local function analyze(cmd)
    local cmd_clean = clean(cmd)
    
    if cmd_clean:search(ld_preload_pattern) then
        return true
    end
    
    return false
end

function on_logline(logline)
    local event_type = logline:gets("observer.event.type")

    if event_type == "EXECVE" or event_type == "PROCTITLE" then
        local command = logline:gets("initiator.command.executed")
        if command and analyze(command) then
            grouper1:feed(logline)
        end
    elseif event_type == "SYSCALL" then
        grouper1:feed(logline)
    end
end

function on_grouped(grouped)
    if grouped.aggregatedData.unique.total < 2 then
        return
    end

    local log_sys = nil
    local log_exec = nil

    for _, event in ipairs(grouped.aggregatedData.loglines) do
        local etype = event:gets("observer.event.type")
        if etype == "SYSCALL" then
            log_sys = event
        elseif etype == "EXECVE" or etype == "PROCTITLE" then
            log_exec = event
        end
    end

    if not log_exec then
        return
    end

    local command_raw = log_exec:gets("initiator.command.executed")
    local command = clean(command_raw)

    if not command then
        return
    end

    local user_name = "Не определен"
    local command_path = "Не определен"
    if log_sys then
        user_name = log_sys:gets("initiator.user.name") or "Не определен"
        command_path = log_sys:gets("initiator.process.path.full") or "Не определен"
    end

    alert({
        template = template,
        meta = {
            user_name = user_name,
            command = command,
            command_path = command_path
        },
        risk_level = 9.0,
        asset_ip = log_exec:get_asset_data("observer.host.ip"),
        asset_hostname = log_exec:get_asset_data("observer.host.hostname"),
        asset_fqdn = log_exec:get_asset_data("observer.host.fqdn"),
        asset_mac = "",
        create_incident = true,
        incident_group = "Persistence",
        assign_to_customer = false,
        incident_identifier = "",
        logs = grouped.aggregatedData.loglines,
        mitre = {"T1574.006", "T1547.008"},
        trim_logs = 10
    })
    grouper1:clear()
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)
