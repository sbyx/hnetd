--[[
LuCI - Lua Configuration Interface

Copyright 2014 Steven Barth <steven@midlink.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

$Id$
]]--

m = Map("hnet", translate("Homenet"),
translate("Overrides for global homenet settings"))

s = m:section(NamedSection, "pa", "pa", translate("Prefix Assignment"))
s.addremove = false

s:option(Value, "ulaprefix", translate("ULA-Prefix"))
s:option(Value, "ip4prefix", translate("IPv4-Prefix"))

s = m:section(NamedSection, "sd", "sd", translate("Service Discovery"))
s:option(Value, "router_name", translate("Router Name"))
s:option(Value, "domain_name", translate("Domain Name"))

return m
