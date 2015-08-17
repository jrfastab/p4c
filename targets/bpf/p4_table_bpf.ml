open P4_table
open P4_counters
open P4_header
open P4_header_type
open P4_header_type_bpf
open P4_primitives_bpf
open P4_parser
open P4_action

let _p4_table_pp_bpf_elf_map ref map_type key_size value_size max_entries =
	"struct bpf_elf_map __section(\"maps\") map_" ^ ref ^ " = {\n" ^
	"\t.type\t\t\t=\t\t" ^ map_type ^ ",\n" ^
	"\t.size_key\t\t=\t\t" ^ key_size ^ ",\n" ^
	"\t.size_value\t\t=\t\t" ^ value_size ^ ",\n" ^
	"\t.max_elem\t\t=\t\t" ^ max_entries ^ ",\n" ^
	"\t.id\t\t\t=\t\tBPF_P4_MAP_" ^ String.uppercase ref ^ ",\n" ^
	"};\n\n"

let _p4_table_map_max_entries table = 
	let t = table.p4_table in

	let size =
	match t.max_size with
	| Some x -> x
	| None -> match t.size with
		| Some x -> x
		| None -> raise (Failure ("table " ^ table.table_ref ^ " must give size\n"))
	in

	string_of_int size

let _p4_table_map_value_size table =
	"sizeof(struct p4_action_value)"


let _p4_table_map_key_size_ebpf table =
	"sizeof(struct p4_" ^ table.table_ref ^ "_flow_keys)" (* try this for now *)


let _p4_table_bpf_elf_map (table : p4_table_ref) =
	let key_size = _p4_table_map_key_size_ebpf table in
	let value_size = _p4_table_map_value_size table in 
	let max_entries =  _p4_table_map_max_entries table in
	let ref = table.table_ref in
	
	_p4_table_pp_bpf_elf_map ref "BPF_MAP_TYPE_HASH" key_size value_size max_entries 

let _p4_table_map_bpf_elf (t : p4_table_ref list) =
	List.fold_left (fun s t -> s ^ _p4_table_bpf_elf_map t) "" (List.rev t)

let _p4_table_map_enum_bpf_elf t cntrs =
	let tlist = List.fold_left (fun s t ->
		s ^ "\tBPF_P4_MAP_" ^ (String.uppercase t.table_ref) ^ ",\n"
	) "" (List.rev t) in

	let clist = List.fold_left (fun s c ->
		s ^ "\tBPF_P4_MAP_" ^ (String.uppercase c.counter_ref) ^ ",\n"
	) "" (List.rev cntrs) in

	"enum {\n" ^
		clist ^ tlist ^
	"\t__BPF_P4_MAP_MAX,\n" ^
	"};\n" ^
	"#define BPF_P4_MAP_MAX __BPF_P4_MAP_MAX\n\n"

let inst_hash = Hashtbl.create 200 (* TBD use size of something *)

let extract_print h f =
	let off = match f.offset_from_header with
		| Int x -> x
		| Unknown -> raise (Failure "unknown lengths unsupported")
	in

	let pp_extract_dec etype =
		"static inline " ^ etype ^ " p4_extract_" ^ h ^ "_" ^ f.field ^ "(" ^
		"struct __sk_buff *skb, uint32_t off)\n" ^
		"{\n"
	in

	let w = match f.bitwidth with
	| Int w -> w
	| Unknown ->
		raise (Failure "unknown lengths not supported yet\n")
	in

	let offset = off / 8 in
	let shift = off mod 8 in
	let mask = (hex_of_ones w) in

	begin
	match w with
	| w when w <= 8 ->
		(pp_extract_dec "__u8") ^
		(_p4_ebpf_primitive_mvu8 "skb" "off" offset shift mask)
	| w when w <= 16 ->
		(pp_extract_dec "__u16") ^
		(_p4_ebpf_primitive_mvu16 "skb" "off" offset shift mask)
	| w when w <= 32 ->
		(pp_extract_dec "__u32") ^
		(_p4_ebpf_primitive_mvu32 "skb" "off" offset shift mask)
	| w when w <= 64 ->
		(pp_extract_dec "__u64") ^
		(_p4_ebpf_primitive_mvu64 "skb" "off" offset shift mask)
	| w ->
		raise (Failure "bit length too large... unsupported\n")
	end

	^ "}\n\n"

let _p4_table_extract_instances (table : p4_table_ref) =
	let _p4_table_extract_instance i =
		match i.field_or_masked_ref with 
		| Field_ref_header h ->
		""
		| Field_ref_field (h, f) ->
			let inst = p4_get_instance_header h in
			let field = p4_get_field inst.header_ref f in
	
			begin
			try
				let v = Hashtbl.find inst_hash (inst.header_ref^field.field) in
				""
			with
				| Not_found -> 
					Hashtbl.add inst_hash (inst.header_ref^field.field) 1;
					extract_print inst.header_ref field
			end

		| Field_ref_mask (h, f, m) ->
	
	""
	in

	let t = table.p4_table in 

	match t.reads with
	| None -> ""
	| Some r ->
		List.fold_left (fun s i -> 
			s ^ (_p4_table_extract_instance i)
		) "" r

let _p4_table_extract_parse_instances p =
	let latest =
		match p.p4_parser.extract_or_set with
		| Some e_or_s ->
			begin
			match e_or_s with
			| Extract e ->
				e.instance
			| Set s -> ""
			end
		| None ->
			""
	in

	match p.p4_parser.return with
	| Value v ->
		begin
		match v with
		| State_function s ->
			""
		| Parse_error s ->
			""
		end
	| Select s ->
		List.fold_right (fun v s ->
			begin
			match v with
			| Current (x,y) -> s
			| Latest str ->
				let hdr = p4_get_instance_header latest in
				let (field : p4_field)= p4_get_field hdr.header_ref str in
				let (e_string :string)= (extract_print hdr.header_ref field) in

				s ^ e_string
			| Field_ref str -> s ^ str
			end
		) s.select ""

let _p4_table_extract_bpf_elf (t : p4_table_ref list) p =
	let reads = List.fold_left (fun s t -> s ^ _p4_table_extract_instances t) "" (List.rev t) in
	let parse = List.fold_left (fun s p -> s ^ _p4_table_extract_parse_instances p) "" (List.rev p) in

	reads ^ parse

let extract_hash = Hashtbl.create 200 (* TBD use size of something *)

let _p4_table_flow_key_print h f =
	"\t" ^ _p4_field_type_ebpf_to_string f.bitwidth ^ " " ^ h ^ "_" ^ f.field ^ ";\n"

let _p4_table_flow_key (s, e) t =
	let _p4_table_flow_key_get (s,e) r =
		match r.field_or_masked_ref with
		| Field_ref_header h -> ("", "")
		| Field_ref_field (h, f) ->
			let inst = p4_get_instance_header h in
			let field = p4_get_field inst.header_ref f in
	
			let struct_field = _p4_table_flow_key_print h field in
			let extract_key =
				begin
				try
					let v = Hashtbl.find extract_hash (h^field.field) in
					""
				with
					| Not_found -> 
						Hashtbl.add extract_hash (h^field.field) 1;
						struct_field
				end
			in

			((s ^ struct_field), (e ^ extract_key))
		| Field_ref_mask (h, f, m) -> (s, e)
	in

	let (s', e') =
	begin
	match t.p4_table.reads with
	| Some reads ->
		List.fold_left (fun i r -> _p4_table_flow_key_get i r) ("","") (List.rev reads)
	| None ->
		("", "")
	end
	in

	((s ^ "struct p4_" ^ t.table_ref ^ "_flow_keys {\n" ^ s' ^ "};\n"), (e ^ e'))

let _p4_parser_flow_keys p =
	let _p4_parser_flow_keys_select latest s =
		match s with
		| Current (x,y) -> ""
		| Latest f ->
			let inst = p4_get_instance_header latest in
			let field = p4_get_field inst.header_ref f in
	
			let struct_field = _p4_table_flow_key_print latest field in
			let extract_key =
				begin
				try
					let v = Hashtbl.find extract_hash (latest^field.field) in
					""
				with
					| Not_found -> 
						Hashtbl.add extract_hash (latest^field.field) 1;
						struct_field
				end
			in

			extract_key
		| Field_ref field -> field
	in

	let latest = match p.p4_parser.extract_or_set with
		| Some e_or_s ->
			begin
			match e_or_s with
			| Extract extract -> extract.instance
			| Set s -> ""
			end
		| None ->
			""
	in

	match p.p4_parser.return with
	| Value r -> ""
	| Select s ->
		List.fold_left (fun s t -> s ^ (_p4_parser_flow_keys_select latest t)) "" s.select 


let _p4_table_flow_key_bpf_elf t p =
	let (flow_keys, extract_keys) =
		List.fold_left (fun s t -> _p4_table_flow_key s t) ("", "") (List.rev t)
	in

	let parser_keys =
		List.fold_left (fun s p -> s ^ (_p4_parser_flow_keys p)) "" p
	in

	let flow_key =
		flow_keys ^ "\n" ^ "struct p4_extract_flow_keys {\n" ^ extract_keys ^ parser_keys ^ "};\n\n"
	in

	flow_key

let _p4_table_to_size cntr table =
	match table.p4_table.size with
	| Some s -> s
	| None ->
		begin
		match table.p4_table.max_size with
		| Some s -> s
		| None ->
			let err_str = Printf.sprintf "counter %s table `%s` invalid size attribute"
					cntr.counter_ref
					table.table_ref
			in
			raise (Failure err_str)
		end

let _p4_table_cntrs_elems cntr tbls =
	match cntr.counter_direct_or_static with
	   | Some x ->
		begin
		match x with
		| P4_Counter_Direct t ->
			let t = List.find (fun table ->
				if ((String.compare table.table_ref t) == 0)
				then true
				else false
			) tbls in

			_p4_table_to_size cntr t
		| P4_Counter_Static t ->
			let t = List.find (fun table ->
				if ((String.compare table.table_ref t) == 0)
				then true
				else false
			) tbls in

			_p4_table_to_size cntr t
		end
	   (* If static or dynamic are not specified we do not have any
	    * hints to generate the size of the counter array so make
	    * something up.
	    *)
	   | None -> 1024

let _p4_table_cntrs_size cntr =
	(* Counters use u64 value on EBPF targets *)
	"sizeof(long)"

let _p4_table_cntrs_keys cntr =
	(* Counters use u32 keys on EBPF targets *)
	"sizeof(uint32_t)"

let _p4_table_cntrs_map cntr tbls =
	let key_size = _p4_table_cntrs_keys cntr in
	let value_size = _p4_table_cntrs_size cntr in
	let max_entries = _p4_table_cntrs_elems cntr tbls in

	_p4_table_pp_bpf_elf_map cntr.counter_ref "BPF_MAP_TYPE_ARRAY"
				 key_size value_size (string_of_int max_entries)

let _p4_table_cntrs tbls cntrs =
	let maps = List.fold_left (fun s c ->
		s ^ (_p4_table_cntrs_map c tbls)
	) "" cntrs in

	let ptrs =
		"static struct bpf_elf_map *bpf_map_ptrs[] = {\n" ^
			(List.fold_left (fun s c -> s ^ "\tmap_" ^ c.counter_ref ^ ",\n") "" (List.rev cntrs)) ^
		"};\n\n"
	in

	maps ^ ptrs

let _p4_table_print_load_keys_ebpf tables =
	List.map (fun t ->
		match t.p4_table.reads with
		| None -> (t.table_ref, "\n")
		| Some r ->
			let stmts =
			List.fold_left (fun s r ->
				match r.field_or_masked_ref with
				| Field_ref_header str ->
					raise (Failure "field ref header unsupported")
				| Field_ref_field (header, field) ->
					s ^ "\t" ^ t.table_ref ^ "_keys." ^ header ^ "_" ^ field ^
					    " = key->" ^ header ^ "_" ^ field ^ ";\n"
				| Field_ref_mask (header, field, mask) ->
					s ^ "\t" ^ t.table_ref ^ "_keys." ^ header ^ "_" ^ field ^
					    " = keys->" ^ header ^ "_" ^ field ^ ";\n"
			) "" r
			^
			"\tvalue = p4_map_lookup_elem(&map_" ^ t.table_ref ^ ", &" ^ t.table_ref ^ "_keys);\n"
			in

			(t.table_ref, stmts)
	) tables

let _p4_table_ebpf_eval_elf tables =
	let lookup_rule = _p4_table_print_load_keys_ebpf tables in
	let eval_table tref stmts =
		"static inline int p4_eval_table_" ^ tref ^ "(struct p4_extract_flow_keys *key, struct __sk_buff *skb)\n" ^
		"{\n" ^
			"\tstruct p4_action_value *value;\n" ^
			"\tstruct p4_" ^ tref ^ "_flow_keys " ^ tref ^ "_keys = {0};\n" ^
			"\tint out = 0;\n" ^
			"\n" ^
			stmts ^ "\n" ^
			"\tif (value)\n" ^
				"\t\tout = ((p4_eval_action(value, skb)) << 1) | 0x1;\n" ^
			"\treturn out;\n" ^
		"}\n\n"
	in

	let eval_funcs = List.map (fun (tref, stmts) -> eval_table (tref) (stmts)) lookup_rule in

	List.fold_left (fun s f -> s ^ f) "" eval_funcs

let _p4_table_ref_ebpf tables p cntrs actions =
	let ebpf_cntrs = _p4_table_cntrs tables cntrs in
	let ebpf_enum = _p4_table_map_enum_bpf_elf tables cntrs in
	let ebpf_map = _p4_table_map_bpf_elf tables in
	let ebpf_extract = _p4_table_extract_bpf_elf tables p in
	let ebpf_flow_keys = _p4_table_flow_key_bpf_elf tables p in
	let ebpf_table_eval = _p4_table_ebpf_eval_elf tables in

	ebpf_extract ^ ebpf_flow_keys ^ ebpf_enum ^ ebpf_map ^ ebpf_cntrs ^ ebpf_table_eval
