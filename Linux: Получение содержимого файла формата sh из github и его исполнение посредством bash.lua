-- Шаблон алерта
local template = [[
	Обнаружено получение содержимого файла формата sh из GitHub и его исполнение посредством bash.

    Узел: 
    {{ if .First.observer.host.ip }}IP - "{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }}
    {{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }}
    Пользователь(инициатор): {{ .Meta.user_name }}
    Выполненная команда: {{ .Meta.command }}
    Окружение, из которого выполнялась команда: {{ .Meta.command_path }}
]]

-- Переменные для групера
local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"observer.event.type"}
local grouped_time_field = "@timestamp,RFC3339"

-- Массив с регулярными выражениями
local git_patterns = {
        "(?:^|\\/|\\s+|\"|\')(?:wget|curl|lwp-download|http)\\s+((-{1,2}[\\w=\\,\\s]+){1,10})?(?:\'|\")(?:http(s)?|www):\\/{2}raw\\.githubusercontent\\.com\\/[^\\s]+[\\.]sh(?:\'|\")(\\s+(?:(-\\w\\s+)|(>\\s+))?((\\/?[^\\/ ]*)+\\/?)\\.\\w{1,5})?",
        "(?:^|\\/|\\s+|\"|\')(?:wget|curl|lwp-download|http)\\s+((-{1,2}[\\w=\\,\\s]+){1,10})?(?:\"|\')?(?:http(s)?|www):\\/{2}raw\\.githubusercontent\\.com\\/[^\\s]+[\\.]sh(?:\"|\')?(\\s+(-\\w\\s+)?((\\/?[^\\/ ]*)+\\/?)\\.\\w{1,5})?",
        "(?:^|\\/|\\s+|\"|\')(?:aria2c|axel)\\s+-{1,2}\\w\\s+[\\w,\\s\\-\\/_]+\\.[\\w]{1,5}\\s+(?:\'|\")?http(s)?:\\/{2}raw\\.githubusercontent\\.com\\/[^\\s]+[\\.]sh(?:\'|\")?",
        "(?:^|\\/|\\s+|\"|\')(?:hub|glab|git|svn|gh)\\s+(?:(repo\\s+)?clone|export|archive)\\s+((-{1,2}[\\w=\\,\\s]+){1,10})?(?:((http(s)?:\\/{2})|@)?github.com(:)?\\/?)?(\\/?[^\\/ ]*)+\\/?(\\.sh)?((\\s+\\S+)?\\s+(\\/?[^\\/ ]*)+\\/?\\.sh)?",
        "(?:^|\\/|\\s+|\"|\')gh\\s+api\\s+((-{1,2}[\\w=\\,\\s]+){1,10})?(\\/?[^\\/ ]*)+\\/?(\\.sh)?(\\s+(-{1,2}(?:[\\w=\\,\\s\\.]+|\\.content)){1,10})?",
        "(?:^|\\/|\\s+|\"|\')python\\d[\\d\\.]{0,3}\\s+-\\w?\\s+(?:\"|\')?([<\'\\w\\s\\.]+)?import\\s+[\\w\\s=\\.;\\(\\)]+(?:\"|\')?http(s)?:\\/\\/raw\\.githubusercontent\\.com\\/([^\\/\\s]+\\/?)+\\.sh(?:\"|\')([\\w\\s\\(\\)\\,\\.:=\'\"]+)?"       
}

-- Универсальная функция: возвращает true/false если проходит регулярка
local function analyze(cmd)
    local cmd_string = cmd:lower()
    
    for _, pattern in pairs(git_patterns) do
            local regular = cmd_string:search(pattern)
            if regular then
                return regular
            end
        
    end
end

-- Функция работы с логлайном
function on_logline(logline)
    if logline:gets("observer.event.type") == "EXECVE" or logline:gets("observer.event.type") == "PROCTITLE" then
		local search_git = analyze(logline:gets("initiator.command.executed"))
        if search_git then
            grouper1:feed(logline)
		end
    else
        grouper1:feed(logline)
    end
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local log_sys = ""
    local log_exec = ""

    for _, event in ipairs(events) do
        if event:gets("observer.event.type") == "SYSCALL" then
            log_sys = event
        else
            log_exec = event
        end
    end

-- Проверяем, что в группере находятся как события EXECVE/PROCTITLE, так и SYSCALL        
    if log_sys ~= "" and log_exec ~= "" then
        local command_executed=log_exec:gets("initiator.command.executed")
        local command_length=command_executed:len().. "..."
        if command_length > 128 then
            command_executed=command_executed:sub(1,128)
        end
        -- Функция алерта
        alert({
            template = template,
            meta = {
                user_name=log_sys:gets("initiator.user.name"),
                command=command_executed,
                command_path=log_sys:gets("initiator.process.path.full")
                },
            risk_level = 8.0, 
            asset_ip = log_exec:get_asset_data("observer.host.ip"),
            asset_hostname = log_exec:get_asset_data("observer.host.hostname"),
            asset_fqdn = log_exec:get_asset_data("observer.host.fqdn"),
            asset_mac = "",
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "",
            logs = grouped.aggregatedData.loglines,
            mitre = {"T1059.004"},
            trim_logs = 10
            }
        )
        grouper1:clear()      
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)