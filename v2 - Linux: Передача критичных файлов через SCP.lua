-- By Alexey Kuprikov
local cf_list = storage.new("cf_list|Linux: Передача критичных файлов через SCP")

local template = [[
Обнаружена передача критичных файлов с помощью утилиты SCP.
На узле: {{ if .First.observer.host.ip }}"{{ .First.observer.host.ip }}"{{ else }}"IP-адрес неопределен"{{ end }} - {{ if .First.observer.host.hostname }}"{{ .First.observer.host.hostname }}"{{ else }}"Имя узла неопределено"{{ end }},
Пользователем: {{ if .First.initiator.user.name }}"{{ .First.initiator.user.name }}"{{ else }}"unknown"{{ end }},
Была выполнена команда: {{ if .First.initiator.command.executed }}"{{ .First.initiator.command.executed }}"{{ else }}"-"{{ end }}.
]]

local detection_window = "1m"
local grouped_by = {"observer.host.ip", "observer.host.hostname"}
local aggregated_by = {"initiator.command.executed"}
local grouped_time_field = "@timestamp,RFC3339"

local pattern_cache = {}
local cache_built = false

local function build_pattern_cache()
    if cache_built then
        return
    end

    local nil_counter = 0

    for i = 1, 1000 do
        local id_str = tostring(i)

        local success, filename_value = pcall(function()
            local key = cf_list:key({
                id = id_str
            })
            return cf_list:get(key, "filename")
        end)

        if success and filename_value then
            table.insert(pattern_cache, filename_value)
            nil_counter = 0
        else
            nil_counter = nil_counter + 1

            if nil_counter >= 3 then
                break
            end
        end
    end

    cache_built = true
end

local function extract_filepath_from_scp(command)
    if not command then
        return nil
    end

    local cleaned = command:gsub("^[%s]*/[%w/]*scp[%s]+", "")
    local filepath = cleaned:match("^([/%w%.%-_]+)")

    return filepath
end

local function convert_regex_pattern(pattern)
    local converted = pattern
    converted = converted:gsub("\\\\", "\\")
    converted = converted:gsub("\\/", "/")
    return converted
end

local function test_regex_match(filepath, pattern)
    local success, result = pcall(function()
        return string.match(filepath, pattern) ~= nil
    end)

    return success and result
end

local function analyze_with_patterns(filepath)
    if not filepath or #filepath == 0 then
        return false, {}
    end

    build_pattern_cache()

    local results = {
        matchedPatterns = {},
        matchedCount = 0,
        details = {}
    }

    for idx, pattern in ipairs(pattern_cache) do
        local lua_pattern = convert_regex_pattern(pattern)

        local matched = test_regex_match(filepath, lua_pattern)

        if matched then
            results.matchedCount = results.matchedCount + 1
            table.insert(results.matchedPatterns, pattern)
            table.insert(results.details, string.format("Паттерн #%d '%s' совпал с путем '%s'", idx,
                pattern, filepath))
        end
    end

    local isDetected = results.matchedCount > 0
    return isDetected, results
end

local function is_critical_file(command)
    if not command then
        return false, nil
    end

    local cmd_lower = command:lower()

    if not cmd_lower:find("scp") then
        return false, nil
    end

    local filepath = extract_filepath_from_scp(command)
    if not filepath then
        return false, nil
    end

    local detected, analysis_results = analyze_with_patterns(filepath)

    return detected, analysis_results
end

local grouper1
function on_grouped(grouped)
    if not grouped or not grouped.aggregatedData or not grouped.aggregatedData.loglines then
        return
    end

    if #grouped.aggregatedData.loglines >= 1 then
        local log_entry = grouped.aggregatedData.loglines[1]
        local command = log_entry:get("initiator.command.executed", "")
        local detected, results = is_critical_file(command)

        if detected and results then
            alert({
                template = template,
                risk_level = 8.0,
                asset_ip = log_entry:get_asset_data("observer.host.ip"),
                asset_hostname = log_entry:get_asset_data("observer.host.hostname"),
                asset_fqdn = log_entry:get_asset_data("observer.host.fqdn"),
                create_incident = true,
                incident_group = "Data_Exfiltration",
                assign_to_customer = false,
                logs = grouped.aggregatedData.loglines,
                mitre = {"T1048.001"},
                trim_logs = 10,
                meta = {
                    matched_patterns = table.concat(results.matchedPatterns, ", "),
                    matched_count = tostring(results.matchedCount),
                    detection_details = table.concat(results.details, "; ")
                }
            })
        end
    end

    grouper1:clear()
end

grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)

function on_logline(logline)
    if not logline then
        return
    end

    local event_category = logline:get("event.category", "")
    local event_subcategory = logline:get("event.subcategory", "")

    if event_category ~= "system_operation" then
        return
    end

    if event_subcategory ~= "command" then
        return
    end

    local command = logline:get("initiator.command.executed", "")
    if command == "" then
        return
    end

    local is_critical, _ = is_critical_file(command)
    if is_critical then
        grouper1:feed(logline)
    end
end