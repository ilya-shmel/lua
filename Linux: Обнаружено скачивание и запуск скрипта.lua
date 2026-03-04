local detection_windows = "5m"
local template = [[
Обнаружено скачивание и запуск скрипта.
Узел: 
{{ if .First.observer.host.hostname }}Hostname - "{{ .First.observer.host.hostname }}"{{end}}
{{ if .First.observer.host.ip }}HostIP - "{{ .First.observer.host.ip }}"{{end}}
Инициатор (пользователь): 
{{if .First.initiator.user.name }}Username - "{{ .First.initiator.user.name }}"{{end}}
{{if .First.initiator.user.id }}UserID - "{{ .First.initiator.user.id }}"{{ end }}
Кол-во найденных команд загрузки: {{ .Meta.downloader_count }}
Кол-во найденных команд bash: {{ .Meta.bash_count }}
Общее количество событий: {{ .Meta.total_events }}
Команда(ы) загрузки файла: {{ .Meta.obtain_command }}
Команда(ы) выполнения файла: {{ .Meta.shell_command }}"
]]


local function classify(cmd)
  local cmd_lower = cmd:lower()
  
  -- Проверка на bash команды
  if cmd_lower:find("bash", 1, true) or cmd_lower:find("/bin/bash", 1, true) then 
    return "bash" 
  end

  if cmd_lower:find("wget", 1, true) or 
     cmd_lower:find("curl", 1, true) or 
     cmd_lower:find("lwp-download", 1, true) or
     cmd_lower:find("ftp", 1, true) or 
     cmd_lower:find("sftp", 1, true) or 
     cmd_lower:find("scp", 1, true) or 
     cmd_lower:find("rsync", 1, true) then
    return "downloader"
  end
  
  return nil
end

function on_logline(logline)
  local event_type = (logline:gets("observer.event.type") or ""):upper()
  
  if event_type == "EXECVE" then
    local command = logline:gets("initiator.command.executed")
    local kind = classify(command)
    
    -- Проверяем, что это нужная нам команда
    if kind then
      grouper1:feed(logline)
    end
  elseif event_type == "SYSCALL" then
    grouper1:feed(logline)
  end
end

-- Кастомная функция сопоставления для более гибкой логики
function on_matched(grouped, matchedData)
  
  command_downloader = {}
  command_bash = {}  
  -- Подсчет событий по типам
  local syscall_count = 0
  local execve_count = 0
  local downloader_count = 0
  local bash_count = 0
  
  for _, logline in ipairs(matchedData.loglines) do
    local et = (logline:gets("observer.event.type") or ""):upper()
    
    if et == "SYSCALL" then
      syscall_count = syscall_count + 1
    elseif et == "EXECVE" then
      execve_count = execve_count + 1
      
      local cmd = logline:gets("initiator.command.executed")
      local kind = classify(cmd)
      
      if kind == "downloader" then
        downloader_count = downloader_count + 1
        table.insert(command_downloader, cmd)
      elseif kind == "bash" then
        bash_count = bash_count + 1
        table.insert(command_bash, cmd)
      end
    end
  end
  
  if syscall_count >= 1 and downloader_count >= 1 and bash_count >= 1 then
    local first = matchedData.loglines[1]
    local commands_downloaders = table.concat(command_downloader, "; ")
    local commands_bash = table.concat(command_bash, "; ")

    local meta = {
      downloader_count = tostring(downloader_count),
      bash_count = tostring(bash_count),
      syscall_count = tostring(syscall_count),
      total_events = tostring(#matchedData.loglines),
      technique = "T1105",
      detection_method = "Sequential Command Analysis",
      obtain_command=commands_downloaders,
      shell_command=commands_bash    
    }
    
    alert({
      template           = template,
      risk_level         = 8.0,
      asset_ip           = first:get_asset_data("observer.host.ip") or "",
      asset_hostname     = first:get_asset_data("observer.host.hostname") or "",
      asset_fqdn         = first:get_asset_data("observer.host.fqdn") or "",
      asset_mac          = "",
      create_incident    = true,
      assign_to_customer = false,
      incident_group     = "Suspicious Activity",
      incident_identifier= "",
      logs               = matchedData.loglines,
      trim_logs          = 10,
      meta               = meta,
      mitre              = {"T1105", "T1059.004", "T1203"}
    })
    
    return true
  end
  
  return false
end

grouper1 = grouper.new_pattern_matcher(
  { "observer.host.hostname", "observer.host.ip" },           
  { 
    "observer.host.hostname", 
    "observer.host.ip", 
    "observer.event.type",
    "initiator.command.executed",
    "initiator.user.name",
    "initiator.user.id",
    "@timestamp"
  },    -- поля агрегации
  { "@timestamp" },                                          
  {
    { field = "observer.event.type", values = { "SYSCALL" }, count = 1 },
    { field = "observer.event.type", values = { "EXECVE" }, count = 2 }
  },                                                         
  
  "@timestamp",                                              
  detection_windows,                                          
  on_matched                                                  
)