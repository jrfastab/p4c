open P4_header_type
open P4_header

let _p4_header_match h =
	let m = p4_get_header_type (String.lowercase h.header_ref) in
	"static char " ^ h.header_instance_name ^ "_str[] = \"" ^ h.header_instance_name ^ "\";\n" ^
	"static __u32 " ^ h.header_instance_name ^ "_headers[] = {HEADER_" ^
		(String.uppercase h.header_ref) ^ ", 0};\n\n" ^
	"static struct net_mat_hdr_node " ^ h.header_instance_name ^ " = {\n" ^
	"\t.name = " ^ h.header_instance_name ^ "_str,\n" ^
	"\t.uid = HEADER_INSTANCE_" ^ (String.uppercase h.header_instance_name) ^ ",\n" ^
	"\t.hdrs = " ^ h.header_instance_name ^ "_headers,\n" ^
	"\t.jump = " ^ h.header_instance_name ^ "_jump,\n" ^
	"};\n\n"

let p4_header_match_node h =
	"\t&" ^ h.header_instance_name ^ ",\n"

let _p4_header_ref_match h =
	let hdr_node = List.fold_left (fun s h -> s ^ _p4_header_match h) "" h in
	let node_list' = List.fold_left (fun s h -> s ^ p4_header_match_node h) "" (List.rev h) in
	let node_list =
		"static struct net_mat_hdr_node *bpf_hdr_nodes[] = {\n" ^
		node_list' ^
		"\tNULL,\n" ^
		"};\n\n" in

	hdr_node ^ node_list

