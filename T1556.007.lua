function on_logline(logline)
    
    local command = (logline.initiator and logline.initiator.command and logline.initiator.command.executed) or "" 
    command = command:lower()    
    
    local forbidden_commands = {
        "get-ptaspylog",
        "install-ptaspy",
        "ptaspy",
        "aadintptaspy",
        "get-aadintptaspylog",
        "-decodepasswords"
    }
    
    for _, pattern in ipairs(forbidden_commands) do
        if string.find(command, pattern) then
            
            local observer_host = logline:get("observer.host") or {}
            if not observer_host.ip or not observer_host.hostname then
                print("Ошибка: отсутствуют обязательные данные актива")
                return
            end
            
            local asset_ip = observer_host.ip or "неизвестный IP"
            local asset_hostname = observer_host.hostname or "неизвестное имя хоста"
            local asset_fqdn = observer_host.fqdn or "неизвестный FQDN"
            
            local user_name = logline:get("initiator.user.name")
            local user_id = logline:get("initiator.user.id") or "неизвестный ID"
            
            local command_executed = logline:get("initiator.command.executed", "") or "неизвестная команда"
            command_executed = truncate(command_executed, 256)
            
            local parent_path = logline:get("initiator.process.parent.path.original") or "неизвестный путь"
            
            local context = {
                First = {
                    Observer = {
                        Host = {
                            IP = asset_ip,
                            Hostname = asset_hostname
                        },
                        Service = {
                            Name = logline:get("observer.service.name") or "неизвестная служба"
                        }
                    },
                    Initiator = {
                        User = {
                            Name = user_name or "неизвестный пользователь",
                            ID = user_id
                        },
                        CommandExecuted = command_executed,
                        ProcessParent = {
                            PathOriginal = parent_path
                        }
                    }
                }
            }
            
            alert({
                template = [[
На узле: "{{.First.Observer.Host.IP }}" - "{{.First.Observer.Host.Hostname }}",
Пользователем: {{if .First.Initiator.User.Name}}{{ .First.Initiator.User.Name }}{{else}}{{ .First.Initiator.User.ID }}{{end}}
Была выполнена команда: "{{.First.Initiator.CommandExecuted}}"
Окружение: {{if .First.Initiator.ProcessParent.PathOriginal}}{{ .First.Initiator.ProcessParent.PathOriginal }}{{else}}{{ .First.Observer.Service.Name }}{{end}}
]],
                risk_level = 8.0,
                create_incident = true,
                logs = {logline},
                mitre = {"T1556.007"},
                context = context
            })
            return 
        end
    end
end