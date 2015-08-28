primitive_action drop(void);
primitive_action count(counter c, value index, packet skb);
primitive_action modify(field src, keyfield h.f);

action drop(void) {
	drop();
}

action count(counter c, value index, packet skb) {
	count(c, index, skb);
}

action dropncount(counter c, value index, packet skb) {
	count(c, index, skb);
	drop();
}

action modify_dstmac(value dstmac) {
	modify(dstmac, linuxethernet_dstmac);
}

counter vlan_pkts_by_vid {
	type : packets;
	direct : a;
}

header_type vlant {
	fields {
		pcp : 3;
		cfi : 1;
		vid : 12;
		ethertype : 16;
	}
}

header_type ethernett {
	fields {
		dstmac : 48;
		srcmac : 48;
		ethertype : 16;
	}
}

header vlant linuxvlan;
header ethernett linuxethernet;

table a {
      reads { linuxvlan.pcp : exact ; linuxvlan.vid : exact; }
      actions { drop; count;} 
      size : 256;
};

table b {
      reads { linuxethernet.srcmac : exact; linuxvlan.vid : exact ; }
      actions { modify_dstmac; drop; } 
      size : 512;
};

table c {
      reads { linuxvlan.vid : exact ; }
      actions { drop; } 
      size : 1024;
};

table d {
      reads { linuxethernet.dstmac : exact ; linuxvlan.cfi : exact ; linuxvlan.vid : exact ; }
      actions { drop; } 
      size : 2048;
};

table e {
      reads { linuxvlan.vid : exact ; }
      actions { drop; } 
      size : 4096;
};

control ingress {
	apply(a);
	apply(b);
	apply(c);
	apply(e);
}

parser parsevlan {
	extract(linuxvlan);
	return ingress;
};

parser parseethernet {
	extract(linuxethernet);
	return select(latest.ethertype) {
		0x08100 : return parsevlan;
		0x08200 : return parsevlan;
		0x08400 : return parsevlan;
	};
};

parser start {
	return parseethernet;
};
