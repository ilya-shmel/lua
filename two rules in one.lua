local detectionwindow = "2m"
local groupedby = {"observer.host.ip", "observer.host.hostname", "target.process.pid"}
local aggregatedby = {"observer.event.type", "target.syscall.name", "target.file.path"}

function on_logline(logline)
    local event_type = logline:gets("observer.event.type")
    local syscall_name = logline:gets("target.syscall.name")
    
    -- Первая группа: SYSCALL (openat, execve) и EXECVE
    if (event_type == "SYSCALL" and (syscall_name == "openat" or syscall_name == "execve")) or 
       event_type == "EXECVE" then
        grouper1:feed(logline)
    -- Вторая группа: PATH и дополнительные SYSCALL
    elseif event_type == "PATH" or 
           (event_type == "SYSCALL" and syscall_name ~= "openat" and syscall_name ~= "execve") then
        grouper1:feed(logline)
    end
end

function on_grouped(grouped)
    if grouped.aggregatedData.aggregated.total >= 4 then -- Минимум 4 события
        -- Подсчет типов событий
        local event_stats = {
            syscall_openat = 0,
            syscall_execve = 0,
            syscall_other = 0,
            execve = 0,
            path = 0
        }
        
        for _, log in ipairs(grouped.aggregatedData.loglines) do
            local type = log:gets("observer.event.type")
            local syscall = log:gets("target.syscall.name")
            
            if type == "SYSCALL" then
                if syscall == "openat" then
                    event_stats.syscall_openat = event_stats.syscall_openat + 1
                elseif syscall == "execve" then
                    event_stats.syscall_execve = event_stats.syscall_execve + 1
                else
                    event_stats.syscall_other = event_stats.syscall_other + 1
                end
            elseif type == "EXECVE" then
                event_stats.execve = event_stats.execve + 1
            elseif type == "PATH" then
                event_stats.path = event_stats.path + 1
            end
        end
        
        -- Проверка условий срабатывания
        local stage1_complete = (event_stats.syscall_openat >= 1 or event_stats.syscall_execve >= 1) and 
                               event_stats.execve >= 1
        local stage2_complete = event_stats.path >= 2 and event_stats.syscall_other >= 1
        
        if stage1_complete and stage2_complete then
            alert{
                template = "Комплексная подозрительная активность обнаружена",
                risklevel = 8.5,
                assetip = grouped.aggregatedData.loglines[1]:getAssetData("observer.host.ip"),
                assethostname = grouped.aggregatedData.loglines[1]:getAssetData("observer.host.hostname"),
                logs = grouped.aggregatedData.loglines,
                meta = event_stats,
                trimlogs = 20
            }
        end
    end
    grouper1:clear()
end

grouper1 = grouper.new(groupedby, aggregatedby, detectionwindow, on_grouped)
