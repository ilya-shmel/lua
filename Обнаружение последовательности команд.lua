-- Обнаружение последовательности команд: sudo vi -c ':!/bin/sh' /dev/null -> /bin/sh
-- Используется обычный группер с отслеживанием последовательности в on_grouped

local detectionwindow = "5m"
local createincident = true
local assigntocustomer = false
local riskscore = 8.5

local groupedby = {"observer.host.hostname", "initiator.user.id"}
local aggregatedby = {"initiator.command.executed", "initiator.process.path.full"}
local groupedtimefield = "timestamp"

local template = [[
Обнаружена последовательность подозрительных команд на хосте {.First.observer.host.hostname}
Пользователь: {.First.initiator.user.name}
Первая команда: sudo vi с эскалацией shell
Вторая команда: /bin/sh
Обнаружено событий: {.Meta.totalevents}
]]

-- Проверка первой команды (sudo vi с эскалацией)
local function is_vi_escape(command)
    if not command then return false end
    local cmd_lower = string.lower(command)
    
    -- Проверяем наличие sudo vi с параметрами выполнения shell
    if string.find(cmd_lower, "sudo") and string.find(cmd_lower, "vi") then
        if string.find(cmd_lower, "-c") or string.find(cmd_lower, ":!") then
            if string.find(cmd_lower, "/bin/sh") or string.find(cmd_lower, "bash") then
                return true
            end
        end
    end
    
    return false
end

-- Проверка второй команды (/bin/sh)
local function is_shell_exec(command, process_path)
    if not command and not process_path then return false end
    
    local cmd_lower = string.lower(command or "")
    local proc_lower = string.lower(process_path or "")
    
    -- Прямой запуск shell
    if string.find(cmd_lower, "/bin/sh") or string.find(proc_lower, "/bin/sh") then
        return true
    end
    
    return false
end

function on_logline(logline)
    local command = logline:gets("initiator.command.executed", "")
    local process_path = logline:gets("initiator.process.path.full", "")
    
    -- Фидим все подозрительные команды в группер
    if is_vi_escape(command) or is_shell_exec(command, process_path) then
        grouper1:feed(logline)
    end
end

function on_grouped(grouped)
    if not grouped or not grouped.aggregatedData or not grouped.aggregatedData.loglines then
        grouper1:clear()
        return
    end
    
    local events = grouped.aggregatedData.loglines
    local totalevents = #events
    
    if totalevents < 2 then
        grouper1:clear()
        return
    end
    
    -- Ищем последовательность: сначала sudo vi, потом /bin/sh
    local found_vi_escape = false
    local found_shell_exec = false
    local vi_timestamp = nil
    local shell_timestamp = nil
    
    for _, event in ipairs(events) do
        local command = event:gets("initiator.command.executed", "")
        local process_path = event:gets("initiator.process.path.full", "")
        local timestamp = event:gets("timestamp", "")
        
        if is_vi_escape(command) then
            found_vi_escape = true
            vi_timestamp = timestamp
        elseif is_shell_exec(command, process_path) and found_vi_escape then
            found_shell_exec = true
            shell_timestamp = timestamp
            break  -- Последовательность обнаружена
        end
    end
    
    -- Алертим только если обнаружена правильная последовательность
    if found_vi_escape and found_shell_exec then
        local firstevent = events[1]
        local hostname = firstevent:gets("observer.host.hostname", "")
        local username = firstevent:gets("initiator.user.name", "")
        local hostip = firstevent:gets("initiator.host.ip", "")
        
        local meta = {
            technique = "T1548.003",
            totalevents = tostring(totalevents),
            hostname = hostname,
            username = username,
            hostip = hostip,
            vi_timestamp = vi_timestamp,
            shell_timestamp = shell_timestamp
        }
        
        alert({
            template = template,
            risklevel = riskscore,
            assetip = hostip,
            assethostname = hostname,
            assetfqdn = hostname,
            assetmac = "",
            createincident = createincident,
            assigntocustomer = assigntocustomer,
            logs = events,
            trimlogs = 10,
            meta = meta,
            mitre = {"T1548.003", "T1059.004"}
        })
    end
    
    grouper1:clear()
end

grouper1 = grouper.new(
    groupedby,
    aggregatedby,
    groupedtimefield,
    detectionwindow,
    on_grouped
)