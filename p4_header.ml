open P4_header_type

type p4_header_ref = {
	header_ref : string;
	header_instance_name : string;
}

(* p4 header routines *)
let p4_header : ((p4_header_ref list) ref) = ref []

let p4_get_instance_header instance =
	let is_instance a =
		if ((String.compare a.header_instance_name instance) == 0) then true else false
	in

	try List.find (is_instance) !p4_header with
	| Not_found ->
		let errstr = Printf.sprintf "p4_get_instance_header: Not_found: %s" instance in
		raise (Failure errstr)

let p4_get_header header =
	let is_header a =
		if ((String.compare a.header_ref header) == 0) then true else false
	in

	try List.find (is_header) !p4_header with
	| Not_found ->
		let errstr = Printf.sprintf "p4_get_header: Not_found: %s" header in
		raise (Failure errstr)

let p4_get_instance_field instance field =
	let h = p4_get_header_type (p4_get_instance_header instance).header_ref in

	List.find (fun f ->
		if (String.compare field f.field) == 0 then
			true
		else false) h.header_type.fields

let p4_add_header_ref h =
	p4_header := (h :: !p4_header)

(* p4 helper routines *)
let p4_instance_is_ethernet ref =
	(* todo: learn this from parse graph + header data to get code
	 * going use named headers for Linux solution.
	 *)
	if (String.compare ref "linuxethernet") == 0 then
		true
	else
		false

let p4_instance_is_vlan ref =
	(* todo: learn this from parse graph + header data to get code
	 * going use named headers for Linux solution.
	 *)
	if (String.compare ref "linuxvlan") == 0 then
		true
	else
		false

let p4_instance_linux_ethernet_print =
(
"	
	__u32 vlan = skb->vlan_present;
	__u32 __volatile__ proto = skb->protocol;

	if (vlan)
		key->linuxethernet_ethertype = 0x8100;
	else
		key->linuxethernet_ethertype = proto;

	key->linuxethernet_srcmac = p4_extract_ethernett_srcmac(skb, *offset);
	key->linuxethernet_dstmac = p4_extract_ethernett_dstmac(skb, *offset);
	
	headers->linuxethernet = *offset;
",
"
	*offset +=14;
"
)

let p4_instance_linux_vlan_print =
(
"
	__u32 vlan = skb->vlan_tci;

	key->linuxvlan_vid = vlan & 0x0fff;
	key->linuxvlan_cfi = (vlan >> 12) & 1;
	key->linuxvlan_pcp = (vlan >> 13);
"
, "")
