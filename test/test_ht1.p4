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

action modify_vid(value src) {
	modify(src, innervlan_vid);
}

counter vlan_pkts_by_vid {
	type : packets;
	direct : a;
}

counter vlan_pkts_by_prio {
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

header vlant innervlan;
header ethernett ethernet;

table a {
      reads { innervlan.pcp : exact ; innervlan.vid : exact; }
      actions { drop; count;} 
      size : 256;
};

table b {
      reads { ethernet.srcmac : exact; innervlan.vid : exact ; }
      actions { drop; } 
      size : 512;
};

table c {
      reads { innervlan.vid : exact ; }
      actions { drop; } 
      size : 1024;
};

table d {
      reads { ethernet.dstmac : exact ; innervlan.cfi : exact ; innervlan.vid : exact ; }
      actions { drop; } 
      size : 2048;
};

table e {
      reads { innervlan.vid : exact ; }
      actions { drop; } 
      size : 4096;
};

control ingress {
	apply(a) {
		hit {
			apply(b);
		}
		miss {
			apply(c);
		}
	}

	apply(e);
}

parser parsevlan {
	extract(innervlan);
	return ingress;
};

parser parseethernet {
	extract(ethernet);
	return select(latest.ethertype) {
		08100 : return parsevlan;
		08200 : return parsevlan;
		08400 : return parsevlan;
		default : return ingress;
	};
};

parser start {
	return parseethernet;
};
