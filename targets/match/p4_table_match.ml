open P4_table
open P4_header
open P4_header_type

let _p4_table_match (table : p4_table_ref) =
	let uref = String.uppercase table.table_ref in

	let size_str = match table.p4_table.size with
	| None -> raise(Failure "C API requires size")
	| Some s ->
		"#define TABLE_" ^ uref ^ "_SIZE " ^ string_of_int s ^ "\n"
	in

	let min_size = match table.p4_table.min_size with
	| None -> ""
	| Some s -> raise(Failure "C API does not support min_size")
	in

	let max_size = match table.p4_table.max_size with
	| None -> ""
	| Some s -> raise(Failure "C API does not support max_size")
	in

	let reads = match table.p4_table.reads with
	| None -> raise(Failure "C API requires specifying reads")
	| Some r -> r
	in

	let strings = "static char " ^ table.table_ref ^ "_str[] = \"" ^ table.table_ref ^ "\";\n" in

	let matches =
	"static struct net_mat_field_ref matches_" ^ table.table_ref ^ "[] = {\n" ^
	begin
	List.fold_left (fun str x ->
		let (header, field) = match x.field_or_masked_ref with
		| Field_ref_header h ->
			raise(Failure "C API does not support header reference")
		| Field_ref_field (h, f) -> (h, f)
		| Field_ref_mask (h, f, m) ->
			raise(Failure "C API does not support Field_ref_mask")
		in

		let tstr = match x.field_match_type with
		| Field_match_type_exact -> "EXACT"
		| Field_match_type_ternary -> "MASK"
		| Field_match_type_lpm -> "LPM"
		| Field_match_type_range | Field_match_type_valid ->
			raise(Failure "C API does not support match type")
		in

		let i = p4_get_instance_header header in
		let h = i.header_ref in
		let f = p4_get_field h field in

		let header = String.uppercase header in
		let field = String.uppercase field in

		str ^
		"\t{ .instance = HEADER_INSTANCE_" ^ header ^ ",\n" ^
		"\t  .header = HEADER_" ^ String.uppercase h ^ ",\n" ^
		"\t  .field = HEADER_" ^ String.uppercase h ^ "_" ^ field ^ ",\n" ^
		"\t  .mask_type = NET_MAT_MASK_TYPE_" ^ tstr ^"},\n"
	) "" (List.sort p4_reads_largest_first reads)
	end
	^ "\t{ .instance = 0, .field = 0},\n" ^
	  "};\n"
	in

	let actions' = match table.p4_table.table_actions with
		| Table_action_spec acts ->
			List.fold_left (fun s act ->
				s ^ "ACTION_" ^ String.uppercase act ^ ", "
			) "" acts
		| Table_action_profile acts -> ""
	in

	let actions = "static __u32 actions_" ^ table.table_ref ^ "[] = {" ^ actions' ^ "0};\n" in

	strings ^ actions ^
	min_size ^ max_size ^ size_str ^ "\n" ^ matches ^ "\n" ^
	"static struct net_mat_tbl bpf_table_" ^ table.table_ref ^ " = {\n" ^
	"\t.name = " ^ table.table_ref ^ "_str,\n" ^
	"\t.uid = TABLE_" ^ uref ^ ",\n" ^
	"\t.apply_action = TABLE_" ^ uref ^ ",\n" ^
	"\t.size = TABLE_" ^ uref ^ "_SIZE,\n" ^
	"\t.matches = matches_" ^ table.table_ref ^ ",\n" ^
	"\t.actions = actions_" ^ table.table_ref ^ ",\n" ^
	"};\n"

let p4_table_match_list tables =
	let table_list = List.fold_left (fun s t ->
		s ^ "\t&bpf_table_" ^ t.table_ref ^ ",\n"
	) "" tables in

	"static struct net_mat_tbl *bpf_table_list[] = {\n" ^
		table_list ^
	"\tNULL,\n" ^
	"};\n\n"


let p4_header_match_enum h =
	"\tHEADER_INSTANCE_" ^ String.uppercase h.header_instance_name ^ ",\n"

let p4_table_match_enum t =
	"\tTABLE_" ^ String.uppercase t.table_ref ^ ",\n"

let _p4_table_ref_match t p c a h =
	let inst_enums' = List.fold_left (fun s h -> s ^ p4_header_match_enum h) "" h in
	let table_list = p4_table_match_list t in
	let table_defs = List.fold_left (fun s t -> s ^ _p4_table_match t) "" t in
	let table_enums' = List.fold_left (fun s t -> s ^ p4_table_match_enum t) "" (List.rev t) in

	let inst_enums =
		"enum bpf_header_instance {\n" ^
		"\tHEADER_INSTANCE_UNSPEC,\n" ^
		inst_enums' ^
		"};\n\n" in

	let table_enums =
		"enum bpf_table_id {\n" ^
		"\tTABLE_UNSPEC = 0,\n" ^
		table_enums' ^
		"\t__TABLE_MAX,\n" ^
		"};\n" ^
		"#define BPF_MAX_TABLES (__TABLE_MAX - 1)\n" ^
		"\n\n" in

	inst_enums ^ table_enums ^ table_defs ^ table_list
