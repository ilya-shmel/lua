-- Параметры конфигурации
local detection_windows = "5m"  -- Окно детекции для группера

-- Функция обработки каждой строки лога
function on_logline(logline)
	if contains({"SetValue", "DeleteKey"}, logline:get("event.result.description", "")) and compare(logline:get("action", ""), "==", "change") and contains({"12", "13"}, logline:get("observer.event.id", "")) and logline:get("target.object.name", ""):contains("Names") then
		grouper1:feed(logline)
	end
end

-- Функция вызываемая при сработке группера
function on_grouped(grouped)
	local logline = grouped.aggregatedData.loglines[1]
	if grouped.aggregatedData.aggregated.total >= 1 then
		alert({template = [[Создание и удаление учетной записи пользователя {{ .First.target.user.name }} за короткий промежуток_времени "
 Была выполнена команда: "{{ .First.initiator.process.command }}",окружение из которого выполнялась команда: "{{ .First.initiator.process.path.name}}", место выполнения: "{{ .First.initiator.command.path.original}}", пользователь, который выполнил команду: "{{ .First.initiator.user.name }}

Рекомендации по устранению угрозы
1. Убедитесь, что создание и удаление учетной записи запланировал и выполнил авторизованный администратор, используя установленные процессы и процедуры управления изменениями.
2. Рассмотрите возможность отслеживания изменений и обновлений рабочих систем с помощью системы управления изменениями (например, системы отслеживания). Сопоставляйте такие события с утвержденными/авторизованными изменениями.
3. Проверьте, не является ли событие ложным срабатыванием. Предположим, учетная запись была создана с ошибками во время установки; зачастую администраторы предпочитают полностью удалить учетную запись и создать ее заново, что приводит к регистрации событий с идентичными идентификаторами и может вызвать подозрения. Для более детального разбора специалисты по аналитике должны изучить другие операции создания учетных записей с похожими параметрами. Такие операции могут предоставить дополнительную информацию об инциденте. Их также следует проверить на стороне клиента.]], 
    risk_level = 4.0,
    asset_ip = logline:get_asset_data("observer.host.ip"),
    asset_hostname = logline:get_asset_data("observer.host.hostname"),
    asset_fqdn = logline:get_asset_data("observer.host.fqdn"),
    asset_mac = logline:get_asset_data(""),
    create_incident = false, incident_group = "",
    assign_to_customer = false,
    incident_identifier = "",
    logs = grouped.aggregatedData.loglines, trim_logs = 1
    })
	
    grouper1:clear()
	end
end

-- Определение паттерна для группера
pattern = {
    { field = "observer.event.id", values = {"13"}, count = 1 },
    { field = "observer.event.id", values = {"12"}, count = 1 },
}

-- Инициализация группера
grouper1 = grouper.new_pattern_matcher(
    {"observer.host.hostname"}, -- поля группировки
    {"observer.host.hostname"}, -- поля аггрегации
    {"@timestamp"},             -- поле события со временем
    pattern,                    -- паттерн с правилами
    "@timestamp",               -- поле времени для группера
    detection_windows,          -- окно детекции
    on_grouped
)