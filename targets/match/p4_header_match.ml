open P4_header_type
open P4_header

let _p4_header_match h =
	let m = p4_get_header_type h.header_ref in
	"static __u32 " ^ h.header_instance_name ^ "[] = {HEADER_" ^
		(String.uppercase h.header_ref) ^ ", 0};\n\n" ^
	"static struct net_mat_hdr_node " ^ h.header_instance_name ^ "[] = {\n" ^
	"\t.name = " ^ h.header_instance_name ^ "_str,\n" ^
	"\t.uid = HEADER_INSTANCE_" ^ (String.uppercase h.header_instance_name) ^ ",\n" ^
	"\t.hdrs = " ^ h.header_instance_name ^ "_headers,\n" ^
	"\t.jump = " ^ h.header_instance_name ^ "_jump,\n" ^
	"};\n"

let _p4_header_ref_match h =
	List.fold_left (fun s t -> s ^ _p4_header_match t) "" h
