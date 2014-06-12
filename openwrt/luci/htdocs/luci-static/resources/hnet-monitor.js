
var hnet = (function() {


	var sizes = {
		default : {
				LENGTH_IFACES: 1,
				WIDTH_IFACES: 2,
				LENGTH_NEIGHBOR: 100,
				WIDTH_NEIGHBOR: 1,
				LENGTH_UPLINK: 100,
				WIDTH_UPLINK: 1,
				LENGTH_BROWSER: 1,
				WIDTH_BROWSER: 1,
				DESIGNATED_IFACE_RADIUS: 120, //Doesn't work for some reason
				IFACE_RADIUS: 80,
			},
		
		}

	var colors = {
		
		default : {
				ROUTER : '#FF9900',
				OWN_ROUTER: '#FF9900',
				UNKNOWN_ROUTER: "grey",
				UPLINK_ROUTER: "#FF99A0",
				IFACE : "#2B7CE9",
				DESIGNATED_IFACE : "red",
				UNKNOWN_IFACE: "grey",
				UPLINK : "violet",
				CONNEXION_UNIDIR : "#009966",
				CONNEXION_BIDIR : "#003333",
				BROWSER : "green"
			},
		home : {
			ROUTER : "#7BCB00",
			OWN_ROUTER: "#7BCB40",
			UNKNOWN_ROUTER: "#B6BCB6",
			UPLINK_ROUTER: "#7BCBC0",
			IFACE : "#C0FB64",
			DESIGNATED_IFACE : "#7BCB00",
			UNKNOWN_IFACE: "#B6BCB6",
			UPLINK : "#B3C2EE",
			CONNEXION_UNIDIR : "#89D414",
			CONNEXION_BIDIR : "#7BCB00",
			BROWSER : "#7BCBA0",
		},
	}

	function clone(object, extend) {
		var o = {};	
		for(var k in object) {
			o[k] = object[k];
		}
		if(extend) {
			for(var k in extend) {
				o[k] = extend[k];
			}
		}
		return o;
	}

	/* Main monitor object */
	function Monitor(container, options) {
		var me = this;
		this.conf = {
			options: {
				smoothCurves : false,
				physics: {
					barnesHut: {
							enabled: true,
						gravitationalConstant: -10000,
						centralGravity: 0.1,
						springLength: 95,
						springConstant: 0.5,
						damping: 0.09
					},
				},
				nodes: {
					allowedToMoveX : true,
					allowedToMoveY : true,
				},
			},
		}
		
		var customColors = (options && ("colors" in options))?options.colors:undefined;
		this.conf.colors = clone(colors.default, customColors);
		
		var customSizes = (options && ("sizes" in options))?options.sizes:undefined;
		this.conf.sizes = clone(sizes.default, customSizes);
		
		this.container = container;
		this.edges = new vis.DataSet();
		this.nodes = new vis.DataSet();
		this.graph = new vis.Graph(this.container, {edges: this.edges, nodes: this.nodes}, this.conf.options);
		this.graph.on('select', function(p) {me.onSelect(p)});
		
		this.graphElements = {}; //Table of objects with onSelect method, identified by an id.
		this.displayCallback = null;
		this.hncp = {};
		this.entities = [];
		this.entityPositions = {};
		this.routers = {};
		this.browser = null;
		this.version = 0;
	}
	
	Monitor.prototype.onSelect = function(properties) {
		var id = properties.nodes[0];
		if(id in this.graphElements) {
			this.graphElements[id].onSelect(id);
		}
	}
	
	Monitor.prototype.displayString = function(s) {
		if(this.displayCallback)
			this.displayCallback(s); 
	}
	
	Monitor.prototype.displayObject = function(o) {
		return this.displayString(JSON.stringify(o, undefined, 2));
	}
	
	Monitor.prototype.setDisplayCallback = function(callback) {
		this.displayCallback = callback;
	}
	
	Monitor.prototype.update = function(hncp) {
		var me = this;
		this.hncp = hncp;
		this.updateDB();
		this.entities.forEach(function(e) {if(e.version != me.version) e.destroy();});
		this.entities.forEach(function(e) {if(e.upgrade) e.upgrade();});
		this.entities.forEach(function(e) {e.draw();});
	}
	
	Monitor.prototype.getRouter = function(id) {
		if(!(id in this.routers)) {
			new Router(this, id);
		}
		this.routers[id].update();
		return this.routers[id];
	}
	
	Monitor.prototype.getBrowser = function(router) {
		if((!this.browser) || (this.browser.router.id != router.id)) {
			new Browser(router);
		}
		this.browser.update();
		return this.browser;
	}
	
	Monitor.prototype.updateDB = function() {
		var me = this;
		this.version++;
		for(var id in this.hncp["nodes"]) {
			var rhncp = hncp["nodes"][id];
			var r = this.getRouter(id);
			if(("self" in rhncp) && rhncp["self"]) {
				this.getBrowser(r);
			}
			
			if("neighbors" in rhncp) 
				rhncp.neighbors.forEach(function(e) {
					var r2 = me.getRouter(e["node-id"]);
					var iface = r.getIface(e["local-link"]);
					var iface2 = r2.getIface(e["neighbor-link"]);
					var n = iface.getNeighbor(iface2);
				});
			
			if("prefixes" in rhncp)
				rhncp.prefixes.forEach(function(e) {
					if("link" in e)
						var iface = r.getIface(e["link"]);
				});
			
			if("addresses" in rhncp)
				rhncp.addresses.forEach(function(e) {
					if("link-id" in e)
						var iface = r.getIface(e["link-id"]);
				});
				
			for(var i = 0; i<rhncp["uplinks"].length; i++) {
				var uplink = r.getUplink(i);
			}
		}
	}
	
	/* Represent a versioned network entity.  */
	NetworkEntity.prototype.constructor = NetworkEntity;
	function NetworkEntity(monitor) {
		this.monitor = monitor;
		this.version = monitor.version;
		this.inGraph = false;
		this.nodes = [];
		this.edges = [];
		this.index = this.monitor.entities.push(this) - 1;
	}
	
	/* Called while updating to a new hncp dump
	 * when an entity is valid. */
	NetworkEntity.prototype.update = function() {
		this.version = this.monitor.version;
	}
	
	/* Called while updating to a new hncp dump
	 * for elements that are not needed anymore. */
	NetworkEntity.prototype.destroy = function() {
		var me = this;
		if(this.inGraph) {
			var fnodes = function(n) {
				var o = {
					x: me.monitor.graph.nodes[n.id].x,
					y: me.monitor.graph.nodes[n.id].y
				};
				me.monitor.entityPositions[n.id] = o;
				me.monitor.nodes.remove(n.id);
				me.removeGraphElement(n.id);
			};
			var fedges = function(n) {
				me.monitor.edges.remove(n.id);
				me.removeGraphElement(n.id);
			};
			this.nodes.forEach(fnodes);
			this.edges.forEach(fedges);
			this.inGraph = false;
		}
		delete this.monitor.entities[this.index];
	}
	
	/* Adds a selectable id to that object */
	NetworkEntity.prototype.addGraphElement = function(id) {
		if(!(id in this.monitor.graphElements))
			this.monitor.graphElements[id] = this;
	}
	
	/* Removes a selectable id to that object */
	NetworkEntity.prototype.removeGraphElement = function(id) {
		if(id in this.monitor.graphElements)
			delete this.monitor.graphElements[id];
	}
	
	/* Called after upgrade. It updates the graph elements. */
	NetworkEntity.prototype.draw = function() {
		var me = this;
		var monitor = this.monitor;
		var fnodes;
		var fedges;
		
		if(this.inGraph) {
			fnodes = function(n) {
				n.x = undefined;
				n.y = undefined;
				monitor.nodes.update(n);
			};
			fedges = function(n) {monitor.edges.update(n)};
		} else {
			fnodes = function(n) {
				if(n["id"] && (n.id in monitor.entityPositions)) {
					n.x = monitor.entityPositions[n.id].x;
					n.y = monitor.entityPositions[n.id].y;
					n.allowedToMoveX = true;
					n.allowedToMoveY = true;
				}
				monitor.nodes.add(n);
			};
			fedges = function(n) {
				monitor.edges.add(n);
			};
		}
		this.inGraph = true;
		
		this.nodes.forEach(fnodes);
		this.edges.forEach(fedges);
	}
	
	Router.prototype = Object.create(NetworkEntity.prototype, {constructor: Router});
	function Router(monitor, id) {
		NetworkEntity.call(this, monitor);
		this.id = id;
		this.node = {id: "r-"+id, label: id.substr(0,6), shape: "circle"};
		this.addGraphElement(this.node.id);
		this.nodes.push(this.node);
		this.ifaces = {};
		this.uplinks = {};
		this.monitor.routers[id] = this;
		this.hncp = null;
	}
	
	Router.prototype.destroy = function() {
		this.removeGraphElement(this.node.id);
		delete this.monitor.routers[this.id];
		NetworkEntity.prototype.destroy.call(this);
	}
	
	Router.prototype.getIface = function(id) {
		if(!(id in this.ifaces)) {
			new Iface(this, id);
		}
		this.ifaces[id].update();
		return this.ifaces[id];
	}
	
	Router.prototype.getUplink = function(id) {
		if(!(id in this.uplinks)) {
			new Uplink(this, id);
		}
		this.uplinks[id].update();
		return this.uplinks[id];
	}
	
	Router.prototype.getName = function() {
		try {
			var r = this.monitor.hncp.nodes[this.id];
			if(!r)
				throw(1);
			if("router-name" in r)
				return r["router-name"];
			for(var i = 0; i<r.zones.length; i++) {
				var n = r.zones[i].domain.split(".");
				if(n[n.length-2] == "home") {
					return n[n.length - 3];
				}
			}
			throw (1);
		} catch(err) {
			return this.id.substr(0,5);
		}
	}
	
	Router.prototype.update = function() {
		this.hncp = this.monitor.hncp.nodes[this.id];
		NetworkEntity.prototype.update.call(this);
	}
	
	Router.prototype.getTitle = function() {
		try {
			var s = "<p>"+this.id+"</p>";
			this.hncp.zones.forEach(function(n) { s+=n.domain+"<br>"})
			return s;
		} catch(err) {
			return this.id+"<br>"+"No info";
		}
	}
	
	Router.prototype.upgrade = function() {
		if(!this.monitor.hncp.nodes[this.id]) {
			this.node.color = this.monitor.conf.colors.UNKNOWN_ROUTER;
		} else if (("uplinks" in this.monitor.hncp.nodes[this.id]) && this.monitor.hncp.nodes[this.id].uplinks.length) {
			this.node.color = this.monitor.conf.colors.UPLINK_ROUTER;
		}else if(this.id == this.monitor.hncp["node-id"]) {
			this.node.color = this.monitor.conf.colors.OWN_ROUTER;
		} else {
			this.node.color = this.monitor.conf.colors.ROUTER;
		}
		this.node.label = this.getName();
		this.node.title = this.getTitle();
	}
	
	Router.prototype.onSelect = function() {
		if(this.monitor.hncp.nodes[this.id]) {
			this.monitor.displayObject(this.monitor.hncp.nodes[this.id]);
		} else {
			this.monitor.displayString("No hncp data from that router.");
		}
	}
	
	Iface.prototype = Object.create(NetworkEntity.prototype, {constructor: Iface});
	function Iface(router, id) {
		NetworkEntity.call(this, router.monitor);
		this.router = router;
		this.id = id;
		this.node = {id: "i-"+id+"-"+router.id, label: id+"", shape:"dot"};
		this.edge = {from: router.node.id, to: this.node.id,
							length: this.monitor.conf.sizes.LENGTH_IFACES, 
							width: this.monitor.conf.sizes.WIDTH_IFACES};
		this.addGraphElement(this.node.id);
		this.nodes.push(this.node);
		this.edges.push(this.edge);
		this.neighbors = [];
		this.router.ifaces[id] = this;
	}
	
	Iface.prototype.destroy = function() {
		delete this.router.ifaces[this.id];
		this.removeGraphElement(this.node.id);
		NetworkEntity.prototype.destroy.call(this);
	}
	
	Iface.prototype.upgrade = function() {
		var hncp = this.monitor.hncp;
		
		if(!(this.router.id in hncp.nodes)) {
			this.node.color = this.monitor.conf.colors.UNKNOWN_IFACE;
			return;
		}
		
		var prefix_present = false;
		var me = this;
		var hncp_p = hncp.nodes[this.router.id]["prefixes"];
		hncp_p.forEach(function(p) {if(p.link == me.id) prefix_present = true;});
		
		if(prefix_present) {
			this.node.radius = this.monitor.conf.sizes.DESIGNATED_IFACE_RADIUS;
			this.node.color = this.monitor.conf.colors.DESIGNATED_IFACE;
		} else {
			this.node.radius = this.monitor.conf.sizes.IFACE_RADIUS;
			this.node.color = this.monitor.conf.colors.IFACE;
		}
		//this.node.title = this.title();
	}
	
	Iface.prototype.getNeighbor = function(iface) {
		var n = null;
		this.neighbors.forEach(function(i) {if (i.neigh_iface == iface) {n = i;} });
		if(!n) {
			n = new Neighbor(this, iface);
		}
		n.update();
		return n;
	}
	
	Iface.prototype.onSelect = function() {
		var me = this;
		var r = hncp.nodes[this.router.id];
		
		if(!r) {
			this.monitor.displayString("No hncp data from that router.");
			return;
		}
		
		var o = {
			"iface-id" : this.id,
			"router-id" : this.router.id,
			"addresses" : [],
			"prefixes" : [],
		}
		
		r.prefixes.forEach(function(p) {if(p.link == me.id) o.prefixes.push(p)});
		r.addresses.forEach(function(p) {if(p["link-id"] == me.id) o["addresses"].push(p["address"]);});
		this.monitor.displayObject(o);
	}
	
	Browser.prototype = Object.create(NetworkEntity.prototype, {constructor: Browser});
	function Browser(router) {
		NetworkEntity.call(this, router.monitor);
		this.router = router;
		this.node = {id: "browser-"+router.id, label:"", shape:"triangle",
						color: this.monitor.conf.colors.BROWSER};
		this.edge = {from: router.node.id, to: this.node.id,
							length: this.monitor.conf.sizes.LENGTH_BROWSER, 
							width: this.monitor.conf.sizes.WIDTH_BROWSER};
		this.nodes.push(this.node);
		this.edges.push(this.edge);
		this.addGraphElement(this.node.id);
		this.monitor.browser = this;
	}
	
	Browser.prototype.onSelect = function() {
		this.monitor.displayString("This element is connected to the router hosting this page.");
	}
	
	Browser.prototype.destroy = function() {
		this.addGraphElement(this.node.id);	
		NetworkEntity.prototype.destroy.call(this);
	}
	
	Neighbor.prototype = Object.create(NetworkEntity.prototype, {constructor: Neighbor});
	function Neighbor(iface, neigh_iface) {
		NetworkEntity.call(this, iface.router.monitor);
		this.iface = iface;
		this.neigh_iface = neigh_iface;
		this.edge = {from: iface.node.id, to: neigh_iface.node.id, 
							length: this.monitor.conf.sizes.LENGTH_NEIGHBOR, 
							width: this.monitor.conf.sizes.WIDTH_NEIGHBOR};
		this.edges.push(this.edge);
		this.ifaceIndex = this.iface.neighbors.push(this) - 1;
	}
	
	Neighbor.prototype.destroy = function() {
		delete this.iface.neighbors[this.ifaceIndex];
		NetworkEntity.prototype.destroy.call(this);
	}
	
	Neighbor.prototype.upgrade = function() {
		var nrid = this.neigh_iface.router.id;
		var me = this;
		var bidir = false;
		if(nrid in this.monitor.hncp.nodes) {
			this.monitor.hncp.nodes[nrid].neighbors.forEach(
				function(p) {
					if(p["node-id"] == me.iface.router.id && p["neighbor-link"] == me.iface.id) 
						bidir = true;
					}
			);
		}
		
		if(bidir) {
			this.edge.color = this.monitor.conf.colors.CONNEXION_BIDIR;
			this.edge.style = "line";
		} else {
			this.edge.color = this.monitor.conf.colors.CONNEXION_UNIDIR;
			this.edge.style = "arrow";
			this.edge.arrowScaleFactor = 0.4;
		}
	}
	
	Neighbor.prototype.onSelect = function() {
		//console.log(this.edge.id);
	}
	
	Uplink.prototype = Object.create(NetworkEntity.prototype, {constructor: Uplink});
	function Uplink(router, id) {
		NetworkEntity.call(this, router.monitor);
		this.router = router;
		this.id = id;
		this.node = {id: "u-"+id+"-"+router.id, shape:"box", fontSize:10};
		this.edge = {from: router.node.id, to: this.node.id,
						length: this.monitor.conf.sizes.LENGTH_UPLINK, 
						width: this.monitor.conf.sizes.WIDTH_UPLINK};
		this.addGraphElement(this.node.id);
		this.nodes.push(this.node);
		this.edges.push(this.edge);
		this.router.uplinks[id] = this;
	}
	
	Uplink.prototype.destroy = function() {
		delete this.router.uplinks[this.id];
		this.removeGraphElement(this.node.id);
		NetworkEntity.prototype.destroy.call(this);
	}
	
	Uplink.prototype.onSelect = function() {
		if(!this.hncp) {
			this.monitor.displayString("No information about this uplink could be found");
		} else {
			this.monitor.displayObject(this.hncp);
		}
	}
	
	Uplink.prototype.getTitle = function() {
		if(!this.hncp) {
			return "No TLV !";
		} else {
			var s = "";
			s += "dhcpv6: "+this.hncp.dhcpv6+"<br>";
			s += "dhcpv4: "+this.hncp.dhcpv4+"<br>";
			this.hncp.delegated.forEach(function(n) {s += " - "+n.prefix+"<br>"});
			return s;
		}
	}
	
	Uplink.prototype.getLabel = function() {
		var s = "";
		this.hncp.delegated.forEach(function(n) { 
			if(!(s=="")) 
				s += "\n";
			s += n.prefix});
		return s;
	}
	
	Uplink.prototype.upgrade = function() {
		if(!this.router.hncp || !this.router.hncp.uplinks[this.id]) {
			this.hncp = null;
		} else {
			this.hncp = this.router.hncp.uplinks[this.id];
		}
		this.node.title = this.getTitle();
		this.node.label = this.getLabel();
		this.node.color = this.monitor.conf.colors.UPLINK;
	}
	
	var module = {
		Monitor : Monitor,
		colors : colors,
		sizes : sizes
	}
	return module;

})();
