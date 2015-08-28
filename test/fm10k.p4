primitive_action drop(void);
primitive_action count(counter counter_ref, value index, packet skb);
primitive_action modify_field(field dest, value value, value mask);
primitive_action set_field_to_hash_index(field dest, field_list_calc, value base, value size);
primitive_action add_header(header hdr);

action drop(void)
{
	drop();
}

action count(counter cntr, value index, packet skb)
{
	count(cntr, index, skb);
}

action set_dst_mac(uint64_t dst_mac)
{
	modify_field(ethernet.dst_mac, dst_mac, 0);
}

action set_src_mac(uint64_t src_mac)
{
	modify_field(ethernet.src_mac, src_mac, 0);
}

action set_ipv4_dst_ip(uint32_t ip)
{
	modify_field(ipv4.dst_ip, ip, 0);
}

action set_ip4_src_ip(uint32_t ip)
{
	modify_field(ipv4.src_ip, ip, 0);
}

action set_udp_src_port(uint16_t port)
{
	modify_field(udp.src_port, port, 0);
}

action set_udp_dst_port(uint16_t port)
{
	modify_field(udp.dst_port, port, 0);
}

action set_tcp_src_port(uint16_t port)
{
	modify_field(tcp.src_port, port, 0);
}

action set_tcp_dst_port(uint16_t port)
{
	modify_field(tcp.dst_port, port, 0);
}

action set_vlan(uint16_t vid, uint8_t pcp)
{
	modify_field(vlan.vid, vid, 0);
	modify_field(vlan.pcp, pcp, 0);
}

action tunnel_encap(uint32_t dst_ip, uint32_t src_ip, uint32_t vni, uint16_t src_port, uint16_t dst_port)
{
	add_header(vxlan);
	modify_field(vxlan.vni, vni);
	modify_field(vxlan.flags, 0x8);

	add_header(udp);
	modify_field(udp.dst_port, dst_port, 0);
	modify_field(udp.src_port, src_port, 0);

	add_header(ip);
	modify_field(ip.dst_ip, dst_ip, 0);
	modify_field(ip.src_ip, src_ip, 0);

	add_header(ethernet);
}

action tunnel_decap()
{
	pop_header(ethernet);
	pop_header(ip);
	pop_header(udp);
	pop_header(vxlan);
}

counter vlan_pkts_by_vid {
	type : packets;
}

header_type vlan_t {
	fields {
		pcp : 3;
		cfi : 1;
		vid : 12;
		ethertype : 16;
	}
}

header_type ethernet_t {
	fields {
		dstmac : 48;
		srcmac : 48;
		ethertype : 16;
	}
}

header_type ipv4_t {
	fields {
		version : 4;
		ihl : 4;
		dscp : 6;
		ecn : 2;
		length : 8;
		identification : 8;
		flags : 3;
		fragment_offset : 13;
		ttl : 1;
		protocol : 8;
		csum : 8;
		src_ip : 32;
		dst_ip : 32;
	}
}

header_type tcp_t {
	fields {
		src_port : 16;
		dst_port : 16;
		seq : 32;
		ack : 32;
		offset : 4;
		reserved : 3;
		flags : 9;
		windows : 8;
		csum : 16;
		urgent : 16;
	}
}

header_type udp_t {
	fields {
		src_ports : 16;
		dst_port : 16;
		length : 16;
		csum : 16;
	}
}

header_type vxlan_t {
	fields {
		flags : 8;
		reserved1 : 24;
		vni : 24;
		reserved2: 8;
	}
}

header_type vlan_gpe_t {
	fields {
		flags : 8;
		reserved1 : 16;
		next_protocol : 8;
		vni : 24;
		reserved2 : 8;
	}
}

header_type nsh_t {
	fields {
		version : 2;
		flags : 2;
		reserved1 : 5;
		length : 6;
		md_type : 8;
		next_protocol : 8;
		service_path_id : 24;
		service_index : 8;	
	}
}

header_type metadata_t {
	fields {
		skb_len : 32;
		pkt_type : 32;
		mark : 32;
		queue_mapping : 32;
		protocol : 32;
		priority : 32;
		ingress_ifindex : 32;
		ifindex : 32;
		tc_index : 32;

		md0 : 32;
		md1 : 32;
		md2 : 32;
		md3 : 32;
		md4 : 32;
	}
}

header vlan_t vlan;
header ethernet_t ethernet;
header ipv4_t ipv4;
header tcp_t tcp;
header udp_t udp;
header vxlan_t vxlan;
header vxlan_gpe_t vxlan_gpe;
header nsh_t nsh;
header metadata_t metadata;

table tcam {
	reads {
		metadata.ingress_ifindex : mask;
		ethernet.dst_mac : mask;
		ethernet.src_mac : mask;
		vlan.vid : mask;
		ipv4.protocol : mask;
		ipv4.dst_ip : mask;
		ipv4.src_ip : mask;
		tcp.src_port : mask;
		tcp.dst_port : mask;
		udp.src_port : mask;
		udp.dst_port : mask;
		vxlan.vni : mask;
		nsh.service_path_id : mask;
		nsh.service_index : mask;
	}
	actions {
		drop;
		count;
		set_egress_port;
		//route_via_ecmp;
		set_vlan;
		count;
	} 
	size : 32768;
};

table tunnel_engineA {
	reads {
		ethernet.sr_cmac : exact;
		ethernet.dst_mac : exact;
		ipv4.src_ip : exact;
		ipv4.dst_ip : exact;
		udp.src_port : exact;
		udp.dst_port : exact;
		tcp.src_port : exact;
		tcp.dst_port : exact;
		vxlan.vni : exact;
	}
	actions {
		drop;
		vxlan_encap;
		vxlan_decap;
		set_dst_mac;
		set_src_mac;
		set_ipv4_dst_ip;
		set_ipv4_src_ip;
		set_tcp_dst_port;
		set_tcp_src_port;
		set_udp_dst_port;
		set_udp_src_port;
		count;
	} 
	size : 4096;
};

table tunnel_engineB {
	reads {
		ethernet.sr_cmac : exact;
		ethernet.dst_mac : exact;
		ipv4.src_ip : exact;
		ipv4.dst_ip : exact;
		udp.src_port : exact;
		udp.dst_port : exact;
		tcp.src_port : exact;
		tcp.dst_port : exact;
		vxlan.vni : exact;
	}
	actions {
		drop;
		vxlan_encap;
		vxlan_decap;
		set_dst_mac;
		set_src_mac;
		set_ipv4_dst_ip;
		set_ipv4_src_ip;
		set_tcp_dst_port;
		set_tcp_src_port;
		set_udp_dst_port;
		set_udp_src_port;
		count;
	} 
	size : 4096;
}

table next_hop {
	reads {
		//tbd
	}
	actions {
		//route
	}
	size : 32768;
}

table mac {
	reads {
		ethernet.dst_mac : exact;
		vlan.vid : exact;
	}
	actions {
		set_egress_port;
		set_md0;
	}
	size : 32768;
}

table l2_lb {
	reads {
		metadata.md0 : exact;
	}
	actions {
		set_egress_port;
	}
	size : 32768;
}

parser parse_tcp {
	extract(tcp);
}

parser parse_udp {
	extract(udp)
	select (latest.dst_port) {
		0x04d2 : return parse_vxlan;
		0x12b6 : return parse_gpe; 
	}
}

parser parse_ipv4 {
	extract(ipv4)
	select(latest.protocol) {
		06 : return parse_tcp;
		11 : return parse_udp;
	};
}

parser parse_vlan {
	extract(vlan);
	select(latest.ethertype) {
		0x0800 : return parse_ipv4;
	};
};

parser parse_ethernet {
	extract(ethernet);
	select(latest.ethertype) {
		0x08000 : return parse_ipv4;
		0x08100 : return parse_vlan;
	};
};

parser start {
	return parse_ethernet;
};

control tunnel_engineA {
	apply(tcam);	
}

control tunnel_engineB {
	apply(tcam);
}

control l2_lb {
	// terminal
}

control mac {
	switch (metadata.md0) {
	1 : l2_lb;
	};
}

control nexthop {
	apply(mac);
}

control ingress {
	apply(tcam);

	switch (metadata.md0) {
		case 1 : apply(tunnel_engineA);
		case 2 : apply(tunnel_engineB);
		default : apply(nexthop);
		};
	};
}
