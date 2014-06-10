
var hnet = (function() {
	
	/* Main monitor object */
	function Monitor(container) {
		var me = this;
		this.conf = {
			LENGTH_IFACES: 1,
			WIDTH_IFACES: 4,
			LENGTH_NEIGHBOR: 100,
			WIDTH_NEIGHBOR: 2,
			LENGTH_UPLINK: 100,
			WIDTH_UPLINK: 2,
			
			colors : {
				ROUTER : '#FF9900',
				OWN_ROUTER: "red",
				UNKNOWN_ROUTER: "grey",
			
				IFACE : "#2B7CE9",
				DESIGNATED_IFACE : "red",
				UNKNOWN_IFACE: "grey",
			
				UPLINK : "violet",
				
				CONNEXION_UNIDIR : "#009966",
				CONNEXION_BIDIR : "#003333",
			},
			
			options: {
				smoothCurves : false,
				groups: {
					router: {
						shape: 'circle',
						value: 5,
						//radius: 100,
					},
					iface: {
						shape: 'dot',
						value: 3,
						//radius: 1,
					},
					uplink: {
						shape: 'box',
						fontSize: 10,
						//value: 3,
						//radius: 20,
					},
				},
				//configurePhysics:true,
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
	
	Monitor.prototype.updateDB = function() {
		this.version++;
		for(var id in this.hncp["nodes"]) {
			var rhncp = hncp["nodes"][id];
			var r = this.getRouter(id);
	
			for(var i = 0; i<rhncp["neighbors"].length; i++) {
				var hncp_n = rhncp["neighbors"][i];
				var r2 = this.getRouter(hncp_n["node-id"]);
				var iface = r.getIface(hncp_n["local-link"]);
				var iface2 = r2.getIface(hncp_n["neighbor-link"]);
				var n = iface.getNeighbor(iface2);
			}
			
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
				me.addGraphElement(n.id);
			};
			fedges = function(n) {
				monitor.edges.add(n);
				me.addGraphElement(n.id);
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
		this.node = {id: "r-"+id, label: id.substr(0,6), group:"router"};
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
		} else if(this.id == this.monitor.hncp["node-id"]) {
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
		this.node = {id: "i-"+id+"-"+router.id, label: id+"", group:"iface"};
		this.edge = {from: router.node.id, to: this.node.id,
							length: this.monitor.conf.LENGTH_IFACES, 
							width: this.monitor.conf.WIDTH_IFACES};
		this.addGraphElement[this.node.id] = this;
		this.nodes.push(this.node);
		this.edges.push(this.edge);
		this.neighbors = [];
		this.router.ifaces[id] = this;
	}
	
	Iface.prototype.destroy = function() {
		delete this.router.ifaces[this.id];
		this.removeGraphElement[this.node.id];
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
			this.node.color = this.monitor.conf.colors.DESIGNATED_IFACE;
		} else {
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
	
	Neighbor.prototype = Object.create(NetworkEntity.prototype, {constructor: Neighbor});
	function Neighbor(iface, neigh_iface) {
		NetworkEntity.call(this, iface.router.monitor);
		this.iface = iface;
		this.neigh_iface = neigh_iface;
		this.edge = {from: iface.node.id, to: neigh_iface.node.id, 
							length: this.monitor.conf.LENGTH_NEIGHBOR, 
							width: this.monitor.conf.WIDTH_NEIGHBOR};
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
		this.node = {id: "u-"+id+"-"+router.id, label: "+", group:"uplink"};
		this.edge = {from: router.node.id, to: this.node.id,
						length: this.monitor.conf.LENGTH_UPLINK, width: this.monitor.conf.WIDTH_UPLINK};
		this.monitor.graphElements[this.node.id] = this;
		this.nodes.push(this.node);
		this.edges.push(this.edge);
		this.router.uplinks[id] = this;
		console.log("New uplink");
	}
	
	Uplink.prototype.destroy = function() {
		delete this.router.uplinks[this.id];
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
	}
	
	var module = {
		Monitor : Monitor,
	}
	return module;

})();
