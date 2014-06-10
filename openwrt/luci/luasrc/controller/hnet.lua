module("luci.controller.hnet", package.seeall)

function index()
	entry({"admin", "status", "hnet"}, template("hnet-status"), _("Homenet"), 50).dependent=false
	entry({"admin", "status", "hnet-dump"}, call("get_hnet_dump")).dependent=false
	entry({"admin", "network", "hnet"}, cbi("admin_network/hnet"), _("Homenet"), 50)
end

function get_hnet_dump()
	luci.http.prepare_content("application/json")
	luci.http.write(luci.util.exec("ubus call hnet dump 2> /dev/null || echo '{\"error\": \"ubus call failed\"}'"))		
end

