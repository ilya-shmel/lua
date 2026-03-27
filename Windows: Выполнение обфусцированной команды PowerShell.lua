local risk_threshold = 4.0

-- Шаблон алерта
local template = [[
Подозрение на обфусцированную команду PowerShell.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Выполнена команда: {{.Meta.command}}
Процесс: {{.Meta.command_path}}   
]]

-- Параметры группера
local detection_window = "2m"
local grouped_by = {"observer.host.ip", "initiator.user.name"}
local aggregated_by = {"observer.host.ip", "initiator.user.name"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения
local prefix = "(?:^|\\s+|\"|\'|`|\\||&|\\\\)?"
local suffix = "(?:$|\\s+|\"|\'|`|\\||&|\\\\)?"
local path_pattern = "c:\\\\program files\\\\powershell\\d+\\\\modules"
local diag_pattern = "c:\\\\windows\\\\temp\\\\sdiag_"

local obfuscation_patterns = {
    {
        name = "ОБНАРУЖЕН ВЫЗОВ",
        score = 3,
        patterns = {prefix.. "(?:invoke|iex)" ..suffix},
        condition = "any"  -- достаточно любого из паттернов
    },
    {
        name = "ЗАПУТЫВАНИЕ ФОРМАТА СТРОКИ", 
        score = 2,
        patterns = {prefix.. "type\\s+(.*)?-f" ..suffix},
        condition = "any"  
    },
    {
        name = "КОДИРОВКА BASE64",
        score = 4,
        patterns = {prefix.. "(?:system\\.text\\.encoding|frombase64|tobase64)" ..suffix},
        condition = "any"
    },
    {
        name = "ЗАПУТЫВАНИЕ СОЕДИНЕНИЯ СИМВОЛОВ",
        score = 3,
        patterns = {prefix.. "(?i)(join)?\\s+(.*)?\\[?char\\]?(\\s+[\\(\\):$\\w\\s\'\"`\\[\\]\\{\\},]+)?" ..suffix},
        condition = "any" 
    },
    {
        name = "МНОГОКРАТНАЯ ЗАМЕНА",
        patterns = {prefix.. "\\.replace" ..suffix},
        condition = "count",  -- особый тип: считаем количество вхождений
        threshold = 2, -- минимальное количество для срабатывания
        multiplier = 1
    },
    {
        name = "ЗАПУТЫВАНИЕ ОБРАТНОГО ХОДА",
        patterns = {prefix.. "`" ..suffix},
        condition = "count", 
        threshold = 2, 
        multiplier = 0.5
    },
    {
        name = "ПРЕОБРАЗОВАНИЕ ЧИСЛОВЫХ МАССИВОВ",
        score = 2,
        patterns = {prefix.. "\\(\\d+,\\s*\\d+" ..suffix},
        condition = any
    }

}

-- Функция вычисления меры хаотичности строки (энтропия Шеннона)
local function calculate_entropy(string)
    local frequency = {}
    local length = #string 
    
    for index = 1, length do
        local char = string:sub(index, index)
        frequency[char] = (frequency[char] or 0) + 1
    end

    local entropy = 0
    
    for _, count in pairs(frequency) do
        local probability = count / length
        entropy = entropy - (probability * math.log(probability) / math.log(2))
    end
    
    return entropy
end

-- Функция проверки команды на обфускацию
local function analyze_obfuscation(cmd)
    local score = 0
    local indicators = {}
    cmd = cmd:lower()

-- Обработка паттернов типа "any"
    for _, item in ipairs(obfuscation_patterns) do
        if item.condition == "any" then
            for _, pattern in ipairs(item.patterns) do
                if cmd:search(pattern) then
                    score = score + (item.score or 0)
                    table.insert(indicators, item.name)
                    break
                end
            end
-- Количественные проверки ("count")
        elseif item.condition == "count" then
            local total_count = 0
-- Считаем общее количество вхождений по всем паттернам
            for _, pattern in ipairs(item.patterns) do
-- Для подсчёта используем gsub
                local count = select(2, cmd:gsub(pattern, ""))
                total_count = total_count + count
            end
            
            log("Total count: " ..total_count)

            local threshold = item.threshold or 1
            if total_count >= threshold then
                local add_count = total_count * (item.multiplier or 1)
                score = score + add_count
                table.insert(indicators, string.format("%s (%d)", item.name, total_count))
            end
        end
    end

-- Анализируем скобки
    local parent_depth = 0    -- текущая глубина (сколько открытых скобок)
    local max_depth = 0      -- максимальная достигнутая глубина
    
    for index = 1, #cmd do
        local char = cmd:sub(index, index)  -- берём очередной символ
    
        if char == "(" then
            parent_depth = parent_depth + 1           -- открыли скобку → глубина +1
            max_depth = math.max(max_depth, parent_depth)  -- обновляем максимум

        elseif char == ")" then
            parent_depth = parent_depth - 1           -- закрыли скобку → глубина -1
        end

        if max_depth > 6 then
            score = score + (max_depth - 6)
            table.insert(indicators, "ЧРЕЗМЕРНОЕ ВЛОЖЕНИЕ")
        end
    end
 
-- Энтропия переменных (динамическая проверка)
    local variable_entropy_total = 0

    for variable in cmd:gmatch("%$([%w_]+)") do
        if #variable > 4 then
            local entropy = calculate_entropy(variable)
            if entropy > 2.5 then
                variable_entropy_total = variable_entropy_total + entropy
                table.insert(indicators, string.format("ВЫСОКАЯ ЭНТРОПИЯ ПЕРЕМЕННОЙ: %s (%.1f)", variable:sub(1, 8), entropy))
            end
        end
    end

    score = score + (variable_entropy_total * 0.3)

    return score, indicators
end

-- Функция обработки логлайна
function on_logline(logline)
    local path_name = logline:gets("initiator.process.path.name"):lower()
    local command_executed = logline:gets("initiator.command.executed")
    local type = type(command_executed)
    
-- Отбрасываем служебные директории
    if path_name:startswith(diag_pattern) or path_name:search(path_pattern) then return end
    local score, indicators = analyze_obfuscation(command_executed)

    log("Score: " ..score)

    if score >= risk_threshold then
        set_field_value(logline, "score", score)
        set_field_value(logline, "indicators", indicators)
        grouper1:feed(logline)
    end
end

-- Функция работы группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local indicator_text = ""
    log("Events in grouper: " ..#events)

    if #events > 0 then
        local best_event = nil
        local max_score = 0
        local best_indicators = {}

        for _, event in ipairs(events) do
            local event_score = event:gets("score")
            local event_indicators = event:gets("indicators")
            
            if event_score > max_score then
                max_score = event_score
                best_event = event

                best_indicators = event_indicators
            end
        end

        if max_score >= risk_threshold and best_event then
            if #best_indicators > 0 then
                indicator_text = "\n\nОБНАРУЖЕНЫЕ ИНДИКАТОРЫ:\n" .. table.concat(best_indicators, ", ")
            end

            local final_risk = math.min(10.0, 7.0 + (max_score * 0.3))
            local command_executed = best_event:gets("initiator.command.executed")
            local patn_name = best_event:gets("initiator.process.path.name")
            local initiator_user = best_event:get("initiator.user.name") or best_event:get("target.user.name") or "Имя пользователя не определено"
            local host_ip = best_event:get("observer.host.ip") or best_event:get("reportchain.collector.host.ip")
            local host_name = best_event:gets("observer.host.hostname", "Имя узла не определено")


            alert({
                meta = {
                    user_name=initiator_user,
                    command=command_executed,
                    command_path=path_name,
                    host_ip=host_ip,
                    hostname=host_name
                },
                template = template,
                risk_level = final_risk,
                asset_ip = best_event:get_asset_data("observer.host.ip"),
                asset_hostname = best_event:get_asset_data("observer.host.hostname"),
                asset_fqdn = best_event:get_asset_data("observer.host.fqdn"),
                asset_mac = "",
                create_incident = true,
                incident_group = "",
                assign_to_customer = false,
                incident_identifier = "",
                logs = events,
                mitre = {"T1558.001", "T1059.001", "T1027"},
                trim_logs = 10
            })
        end
    end
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)