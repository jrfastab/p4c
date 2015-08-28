open P4_table
open P4_table_bpf
open P4_header_type
open P4_header
open P4_parser
open P4_control

(* Special ingress parser value indicates jump to pipeline. Should this
 * be handled by the parser as a type?
 *)
let ingress = "ingress"
	
let _p4_parser_is_needed_key k = 
	begin
	try
		Hashtbl.find P4_table_bpf.extract_hash k;
		true
	with
		| Not_found ->  false
	end

let _p4_parser_print_classifier_header_ebpf =
"__section(\"classifier\") int cls_main(struct __sk_buff *skb)
{
	uint32_t offset = 0;
	struct p4_extract_flow_keys key = {0};
	struct p4_header_ptrs_t headers = {0};

"

let _p4_parser_print_classifier_end_ebpf =
"	
	skb->mark = control_ingress(&key, &headers, skb);
	return TC_ACT_UNSPEC;
}

__section(\"action-mark\") int act_mark_main(struct __sk_buff *skb)
{
	return skb->mark;
}

char __license[] __section(\"license\") = \"GPL\";
"

let _p4_parser_print_classifier_calls_ebpf calls =
	List.fold_right(fun s c -> s ^ c) (List.rev(calls)) ""

let _p4_parser_nodes nodes =
	let _p4_parser_next_node_print_select select latest =
		let fields = List.mapi (fun i s ->
			let str = match s with
			| Field_ref s -> s
			| Current (i, j) -> ""
			| Latest s -> latest ^ "_" ^ s
			in

			if (List.length select == i + 1) then
				"key->" ^ str
			else
				"key->" ^ str ^ " | " 
			) select
		in

		let fieldstr = List.fold_right (fun s p -> s ^ p) fields "" in

		"\tswitch (" ^ fieldstr ^ ") {\n"
	in

	let _p4_parser_next_node_print_value_or_masked v =
		match v with
		| Value_or_masked_value (z, v) ->
			string_of_int(v)
		| Value_or_masked_mask (z, v, m) ->
			string_of_int(v) ^ " & " ^ string_of_int(m)		
		| Value_or_masked_name name ->
			let err_str = Printf.sprintf "value sets not supported: %s\n" name in
			raise (Failure "unsuported mask name\n")
	in

	let _p4_parser_next_node_print_return return =
		let node = match return with
			| State_function s -> s
			| Parse_error s -> s
		in

		let node_str =
		if (String.compare node ingress) != 0 then
			"\t\tp4_parser_" ^ node ^ "(key, headers, skb, offset);\n"
		else
			""
		in

		node_str ^ "\t\tbreak;\n"
	in
 
	let _p4_parser_next_node_print_case c =
		List.fold_right (fun c s ->
			match c.value_list with
			| Value_or_masked v ->
				s ^
				List.fold_right (fun v s ->
					let expr = _p4_parser_next_node_print_value_or_masked v in
					let next_parser = _p4_parser_next_node_print_return c.case_return_value in

					s ^ "\tcase " ^ expr  ^ " :\n" ^ next_parser
				) v ""
			| Default ->
				let next_parser = _p4_parser_next_node_print_return c.case_return_value in
				s ^ "\tdefault :\n" ^ next_parser
		) (List.rev c) ""	
		^ "\t}\n"
	in

	let _p4_parser_next_node p =
		let extract = 
			match p.p4_parser.extract_or_set with
			| Some e_or_s ->
				begin
				match e_or_s with
				| Extract e ->
					("\tp4_extract_header_" ^ e.instance ^ "(key, headers, skb, offset);\n\n", e.instance) 
				| Set s ->
					raise (Failure "bpf does not support set parser block yet\n")
				end
			| None ->
				("", "")
		in
		let switch_case latest =
			match p.p4_parser.return with
			| Value v ->
				begin
				match v with
				| State_function extract ->
					let node_str =
						if (String.compare extract ingress) != 0 then
							"\tp4_parser_" ^ extract ^ "(key, headers, skb, offset);\n"
						else
							""
					in
					node_str ^ "\treturn;\n"
				| Parse_error err ->
					let err_str = "Parse error `" ^ err ^ "` jump not supported" in
					raise (Failure err_str)
				end
			| Select select ->
				(_p4_parser_next_node_print_select select.select latest) ^
				_p4_parser_next_node_print_case select.case
		in

		let (e, latest) = extract in
		let s = switch_case latest in 

		"static inline void p4_parser_" ^ p.parser_ref ^ "(struct p4_extract_flow_keys *key, struct p4_header_ptrs_t *headers, struct __sk_buff *skb, uint32_t *offset)\n" ^
		"{\n" ^
		e ^ s ^
		"}\n\n"
	in

	List.fold_right (fun p s -> s ^ _p4_parser_next_node p) (nodes) ""

let _p4_parser_ebpf p calls =
	let _p4_parser_header_offset htype =
		let w = match htype.header_type.length with
		| Some l ->
			begin
			match l with
			| INT w -> w
			| FIELD f ->
				let err_str =
					Printf.sprintf "parser %s: length `%s` field names not supported\n"
						p.parser_ref f
				in
				raise (Failure err_str)
			| BINOP (l1, op, l2) ->
				let err_str =
					Printf.sprintf "parser %s: ops not supported\n" p.parser_ref
				in
				raise (Failure err_str)
			end
				
		| None ->
			List.fold_left (
			fun acc f ->
				begin
				match f.bitwidth with
				| Int w -> acc + w
				| Unknown ->
					let err_str =
						Printf.sprintf "parser %s: field ref %s, unkown length\n"
							p.parser_ref f.field
					in
					raise (Failure err_str)
				end
			) 0 htype.header_type.fields 
		in

		"\t*offset += " ^ (string_of_int (w / 8)) ^ "; /* Advance to end of " ^ htype.header_type_ref ^ " */\n"
	in

	let _p4_parser_extract_field_print instance hdr f =
		"\tkey->" ^ instance ^ "_" ^ f.field ^ " = p4_extract_" ^ hdr ^ "_" ^ f.field ^ "(skb, *offset);\n"
	in

	let _p4_parser_extract_fields htype instance_ref =
		(* Linux puts 802.1Q header in OOB skb data fields so we need to
		 * fixup the 802.1Q headers and L2 Ethernet header parsing to
		 * to use the metadata.
		 *)
		let (load_keys, new_offset) =
			if p4_instance_is_ethernet instance_ref then
				p4_instance_linux_ethernet_print
			else if p4_instance_is_vlan instance_ref then
				p4_instance_linux_vlan_print
			else
				let load_keys' = List.fold_left(
				fun s f ->
					let k = instance_ref ^ f.field in
	
					match _p4_parser_is_needed_key k with
					| true -> s ^ (_p4_parser_extract_field_print instance_ref htype.header_type_ref f)
					| false -> s
				) "" htype.header_type.fields in

				let load_keys = try 
					let exists = List.find (fun header ->
						if (String.compare (header) instance_ref) == 0 then true else false
					) !P4_actions_bpf.p4_header_mods  in
					load_keys' ^ "\tp4_header_ptrs.linuxethernet = *offset;\n"
					with | Not_found -> load_keys'
				in

				let new_offset = _p4_parser_header_offset htype in

				(load_keys', new_offset)
		in

		(load_keys, new_offset)
	in

	let p4_parser_extract_header_print hdr stmts calls =
		let call = "\tp4_extract_header_" ^ hdr ^ "(&key, headers, skb, &offset);\n" 
		in
		let func =
"static inline void p4_extract_header_" ^ hdr ^ "(struct p4_extract_flow_keys *key, struct p4_header_ptrs_t *headers, struct __sk_buff *skb, uint32_t *offset)\n" ^
"{\n" ^
	stmts ^
"}\n\n"
		in

		(func, call :: calls)
	in

	let e_or_s calls = 
		match p.p4_parser.extract_or_set with
		| Some e_or_s ->
			begin
			match e_or_s with
			| Extract extract ->
				let instance = extract.instance in
				let itype =
				try
					p4_get_instance_header instance
				with 
				| Not_found ->
					let err_str =
						Printf.sprintf "parser %s: reference unknown instance `%s`\n"
								p.parser_ref instance
					in
					raise (Failure err_str)
				in

				let htype =
				try
					p4_get_header_type itype.header_ref
				with
				| Not_found ->
					let err_str =
						Printf.sprintf "parser %s: reference unknown header %s <- instance `%s`\n"
							p.parser_ref itype.header_ref instance
					in
					raise (Failure err_str)
				in

				let (load_keys, new_offset) = _p4_parser_extract_fields htype instance in

				p4_parser_extract_header_print instance (load_keys ^ new_offset) calls
			| Set s ->
				("", calls)
			end
		| None ->
			("", calls) 
	in
	e_or_s calls

let rec p4_parser_control_case_list action_case =
	let cases = List.fold_left (fun s case ->
		let c = match case.control_action with
		| Action_default ->
			"default: "
		| Action_hit ->
			"\tcase 0x1:\n"
		| Action_miss ->
			"\tcase 0x0:\n"
		| Action_name s ->
			raise (Failure "TBD")
		in

		let block = "\t\t" ^ p4_parser_control_block case.control_action_block in

		s ^ c ^ block
	) "" action_case in

	"\tswitch (hit) {\n" ^ cases ^ "\t};\n"

and p4_parser_control_block_stmt stmt =
	match stmt with
	| Apply_table_call call ->
		"hit = p4_eval_table_" ^ call ^ "(key, headers, skb);\n"
	| Apply_and_select_block select ->
		"hit = p4_eval_table_" ^ select.control_table ^ "(key, headers, skb);\n" ^
		begin
		match select.control_case_list with
		| Action_case action_case ->
			p4_parser_control_case_list action_case
		end
	| If_else_statement stmt -> "TBD\n"
	| Control_fn_name stmt -> "TBD\n"

and p4_parser_control_block b =
	match b with
	| Action_control_block stmt ->
		p4_parser_control_block_stmt stmt

let _p4_parser_control_block block =
	let if_hit_goto =
"	if (hit & (~1)) goto done;\n\n"
	in
	List.fold_left (fun s stmt -> s ^ "\t" ^ (p4_parser_control_block_stmt stmt) ^ if_hit_goto) "" block

let _p4_parser_control control =
	List.fold_left (fun s ctrl ->
		s ^
		"static inline int control_" ^ ctrl.control_ref ^ "(struct p4_extract_flow_keys *key, struct p4_header_ptrs_t *headers, struct __sk_buff *skb)\n" ^
		"{\n" ^
			"\tuint32_t hit = 0;\n\n" ^
			_p4_parser_control_block ctrl.control_block ^
		"done:\n" ^
			"\treturn (hit >> 1);\n" ^
		"}\n\n"
	) "" control

let _p4_parser_ref_ebpf t p c =
	let (stmts, calls) =
		List.fold_left (fun (s,c) p ->
			let (stmt, calls) = _p4_parser_ebpf p c in 
			(s ^ stmt, calls)
		) ("",[]) (List.rev p) in

	let classifier_extract = "\tp4_parser_start(&key, &headers, skb, &offset);\n" in
	let classifier_start = _p4_parser_print_classifier_header_ebpf in
	let control = _p4_parser_control c in
	let classifier_end = _p4_parser_print_classifier_end_ebpf in
	let next_node = _p4_parser_nodes p in

	stmts ^
	next_node ^
	control ^
	classifier_start ^
	classifier_extract ^ "\n" ^
	classifier_end
