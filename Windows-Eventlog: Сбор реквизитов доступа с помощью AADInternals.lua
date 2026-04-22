-- Шаблон алерта
local template = [[
Подозрение на сбор реквизитов доступа с помощью AADInternal.

ЦЕЛЕВОЙ УЗЕЛ:
IP-адрес: {{ .Meta.host_ip }}
Имя узла: {{ .Meta.hostname }}
Пользователь (инициатор): {{ .Meta.user_name }}
Инструменты AADInternal: {{ .Meta.images}}
Выполнена команда: {{.Meta.command}}
Служба: {{.Meta.service}}   
]]

-- Параметры группера
local detection_window = "3m"
local grouped_by = {"observer.host.ip", "observer.host.hostname", "observer.event.id"}
local aggregated_by = {"target.image.name"}
local grouped_time_field = "@timestamp,RFC3339"

-- Регулярные выражения, шаблоны
local pta_patterns = { 
                    "aadinternals.psd1",
                    "azureadconnectapi.ps1",
                    "complianceapi.ps1",
                    "iputils.ps1",
                    "onedrive.ps1",
                    "sara.ps1",
                    "aadinternals.psm1",
                    "azureadconnectapi_utils.ps1",
                    "complianceapi_utils.ps1",
                    "kerberos.ps1",
                    "onedrive_utils.ps1",
                    "sara_utils.ps1",
                    "accesspackages.ps1",
                    "azurecoremanagement.ps1",
                    "kerberos_utils.ps1",
                    "onenote.ps1",
                    "spmt.ps1",
                    "accesstoken.ps1",
                    "azuremanagementapi.ps1",
                    "configuration.ps1",
                    "killchain.ps1",
                    "msappproxy.ps1",
                    "outlookapi.ps1",
                    "spmt_utils.ps1",
                    "accesstoken_utils.ps1",
                    "azuremanagementapi_utils.ps1",
                    "dcaas.ps1",
                    "killchain_utils.ps1",
                    "msappproxy_utils.ps1",
                    "outlookapi_utils.ps1",
                    "spo.ps1",
                    "activesync.ps1",
                    "b2c.ps1",
                    "dcaas_utils.ps1",
                    "mscommerce.ps1",
                    "provisioningapi.ps1",
                    "spo_utils.ps1",
                    "activesync_utils.ps1",
                    "federatedidentitytools.ps1",
                    "mdm.ps1",
                    "msgraphapi.ps1",
                    "provisioningapi_utils.ps1",
                    "syncagent.ps1",
                    "adfs.ps1",
                    "cba.ps1",
                    "graphapi.ps1",
                    "mdm_utils.ps1",
                    "msgraphapi_utils.ps1",
                    "prt.ps1",
                    "teams.ps1",
                    "adminapi.ps1",
                    "cloudshell.ps1",
                    "graphapi_utils.ps1",
                    "mfa.ps1",
                    "mspartner.ps1",
                    "prt_utils.ps1",
                    "teams_utils.ps1",
                    "adminapi_utils.ps1",
                    "cloudshell_utils.ps1",
                    "hybridhealthservices.ps1",
                    "mfa_utils.ps1",
                    "mspartner_utils.ps1",
                    "pta.ps1",
                    "commonutils.ps1",
                    "hybridhealthservices_utils.ps1",
                    "officeapps.ps1"
}

-- Функция, которая удаляет повторяющиеся элементы в массиве
local function check_array(array)
    local seen = {}
    local result = {}
    
    for _, element in ipairs(array) do
        if seen[element] == nil then
            seen[element] = true
            table.insert(result, element)
        end
    end
    
    return result
end

-- Стандартная функция анализа строки
local function analyze(cmd)
    local cmd = cmd:lower()
    local aad_commandlet = contains(pta_patterns, cmd, "sub")
      
    if aad_commandlet then
        return true
    end

    return false
end

-- Функция работы с логлайном
function on_logline(logline)
    local initiator_file = logline:gets("initiator.file.name")
    local is_aadinternals = analyze(initiator_file)

    if is_aadinternals then
        local image_name = initiator_file:match("[^\\]+$")
        set_field_value(logline, "target.image.name", image_name)
        grouper1:feed(logline)
    end
    
end

-- Функция сработки группера
function on_grouped(grouped)
    local events = grouped.aggregatedData.loglines
    local unique_events = grouped.aggregatedData.unique.total
    local first_event = events[1]
    local users = {}
    local target_images = {}
    local commands = {}

    if unique_events > 1 then
        for _, event in ipairs(events) do
            table.insert(users, event:gets("initiator.user.name", "Пользователь не определён"))
            table.insert(target_images, event:gets("target.image.name", "Командлет не определен"))
            table.insert(commands, event:gets("initiator.command.executed", "Команда не определена"))
        end

        users = check_array(users)
        target_images = check_array(target_images)
        commands = check_array(commands)

        local all_users = table.concat(users, ", ")
        local all_images = table.concat(target_images, ", ")
        local all_commands = table.concat(commands, ", ") 

        local host_ip = first_event:get("observer.host.ip") or first_event:get("reportchain.collector.host.ip")
        local host_name = first_event:gets("observer.host.hostname", "Имя узла не определено")
        local host_fqdn = first_event:gets("observer.host.fqdn")
        local service_name = first_event:gets("observer.service.name")

         alert({
            template = template,
            meta = {
                user_name=all_users,
                command=all_commands,
                images=all_images,
                service=service_name,
                host_ip=host_ip,
                hostname=host_name
                },
            risk_level = 8.0, 
            asset_ip = host_ip,
            asset_hostname = host_name,
            asset_fqdn = host_fqdn,
            asset_mac = "",
            create_incident = true,
            incident_group = "",
            assign_to_customer = false,
            incident_identifier = "",
            logs = events,
            mitre = {"T1556.007"},
            trim_logs = 10
            }
        )
       grouper1:clear()
    end
end

-- Группер
grouper1 = grouper.new(grouped_by, aggregated_by, grouped_time_field, detection_window, on_grouped)