whitelist = storage.new("wl_hostname_initUser|Linux: Очищение правил в цепочке iptables")

local template = [[
	{{ .Meta.header}}.
	Узел: {{if .First.observer.host.hostname }} hostname - "{{ .First.observer.host.hostname }}"{{end}}{{if .First.observer.host.ip }} IP - "{{ .First.observer.host.ip }}"{{end}}.
	Выполненная команда: "{{ .Meta.command }}".
	Инициатор: "{{ .Meta.user_name }}".
]]

local function has_flush(cmd)
  local s = cmd:lower()
  local a = s:find("([%w%/%-]*ip6?tables)%s+%-f%s+")
  local b = s:find("([%w%/%-]*ip6?tables)%s+%-f$")
  if not a and not b then
    a = s:find("([%w%/%-]*ip6?tables)%s+%-%-flush%s+")
	b = s:find("([%w%/%-]*ip6?tables)%s+%-%-flush$")
  end
  return a or b
end

local function extract_chain(cmd)
  local s = cmd:lower()
  local a,b,flag,chain = s:find("([%w%/%-]*ip6?tables)%s+%-%-flush%s+([%w_-]+)")
  --log(a)
  if not a then
    a,b,flag,chain = s:find("([%w%/%-]*ip6?tables)%s+%-f%s+([%w_-]+)")
	--log(a)
  end
  if a then
    return chain
  end
  return nil
end

-- Универсальная функция: возвращает true/false если есть flush и имя цепочки или nil
local function analyze(cmd)
  if not has_flush(cmd) then
    return false, nil -- нет очистки цепочек
  end
  local chain = extract_chain(cmd)
  return true, chain -- true — flush найден; chain может быть nil (если не указано)
end


function on_logline(logline)
	if logline:gets("observer.event.type") == "EXECVE" or logline:gets("observer.event.type") == "PROCTITLE" then
		local is_iptables_command, chain = analyze(logline:gets("initiator.command.executed"))
		if is_iptables_command then
			grouper1:feed(logline)
		end
	else
		grouper1:feed(logline)
	end
end

function on_grouped(grouped)
	if grouped.aggregatedData.unique.total > 1 then
		local log_exec = ""
		local log_sys = ""
		for _, log in ipairs(grouped.aggregatedData.loglines) do
			if log:gets("observer.event.type") == "SYSCALL" then
				log_sys = log
			else
				log_exec = log
			end
		end

		if whitelist:get(log_sys:gets("observer.host.hostname").."_"..log_sys:gets("initiator.user.name"), "username") == nil then
			local command = log_exec:gets("initiator.command.executed")
			local is_iptables_command, chain = analyze(command)
			local header = nil
			if chain then 
				header = "Обнаружено очищение правил iptables в цепочке: "..chain
			else
				header = "Обнаружено очищение правил iptables во всех цепочках"
			end
			alert({template = template, meta = { user_name=log_sys:gets("initiator.user.name"), header=header, command=command}, risk_level = 7.0, asset_ip = log_exec:get_asset_data("observer.host.ip"), asset_hostname = log_exec:get_asset_data("observer.host.hostname"), asset_fqdn = log_exec:get_asset_data("observer.host.fqdn"), asset_mac = log_exec:get_asset_data(""), create_incident = true, incident_group = "", assign_to_customer = false, incident_identifier = "", logs = grouped.aggregatedData.loglines, mitre = {"T1562.001"}, trim_logs = 10})
			grouper1:clear()
		end
	end
end
grouper1 = grouper.new({"observer.host.ip", "observer.host.hostname", "observer.event.id"}, {"observer.event.type"}, "@timestamp,RFC3339", "1m", on_grouped)