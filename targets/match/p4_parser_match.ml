open P4_parser
open P4_header_type
open P4_header

let _p4_parser_ref_p4 (x : p4_parser_ref) =
	"parser " ^ x.parser_ref ^ " {\n" ^
		  "}\n"

let p4_get_parser_extract x =
	match x.p4_parser.extract_or_set with
		| Some x ->
			begin
			match x with
			| Set x ->
				raise(Failure "metadata set not supported")
			| Extract x ->
				begin
				match x.index with
				| Some y ->
					raise(Failure "index not yet supported")
				| None ->
					x.instance
				end
			end
		| None ->
			""

let p4_lookup_extract_from_function parsefun p =
	let ref = List.find (fun p ->
		if (String.compare p.parser_ref  parsefun) == 0
		then true
		else false) p in

	p4_get_parser_extract ref	

let _p4_parser_match (x : p4_parser_ref) set =
	let _p4_parser_field_to_bitwidth_str f =
		match f.bitwidth with
		| Int b ->
			begin
			match b with
			| x when x <= 8 -> "u8"
			| x when x <= 16 -> "u16"
			| x when x <= 32 -> "u32"
			| x when x <= 64 -> "u64"
			| x -> raise(Failure "max bitwidth 64.\n")
			end
		| Unknown ->
			raise(Failure "only parse on known length fields.\n")
	in
	let mask_of_bits bits =
		match bits with
		| x when (String.compare bits "u8") == 0 -> "0xff"
		| x when (String.compare bits "u16") == 0 -> "0xffff"
		| x when (String.compare bits "u32") == 0 -> "0xffffffff"
		| x when (String.compare bits "u64") == 0 -> "0xffffffffffffffff"
		| x -> raise(Failure "unkown bit type")
	in

	let node = match x.p4_parser.extract_or_set with
		| Some x ->
			begin
			match x with
			| Set x ->
				raise(Failure "metadata set not supported")
			| Extract x ->
				begin
				match x.index with
				| Some y ->
					raise(Failure "index not yet supported")
				| None ->
					x.instance
				end
			end
		| None ->
			""
	in

	let jump_table_fields = match x.p4_parser.return with
		| Value v -> 
			begin
			match v with
			| State_function f ->
				"" (* TBD *)
			| Parse_error err ->
				let errstr = Printf.sprintf "%s: Parse errors unsupported\n" err in
				raise (Failure errstr)
			end
		| Select v ->
			let select = List.fold_left (fun s v ->
				match v with
				| Latest x ->
					(node, (String.lowercase x)) :: s
				| Current (x, y) ->
					raise(Failure "select current not supported")
				| Field_ref x -> (node, (String.lowercase x)) :: s
			) [] v.select in (* TBD: how do we have multiples of these? *)

			let values = 
			List.fold_left (fun xs v ->
				let value_list = match v.value_list with
					| Value_or_masked l ->
						l	
					| Default ->
						raise(Failure "default not supported") 
				in
				(value_list, v.case_return_value) :: xs
			) [] v.case in

			(* Below assumes latest for now *)
			let (header, field) = List.hd select in
			let h = (p4_get_instance_header header).header_ref in
			let bitwidth = _p4_parser_field_to_bitwidth_str
					(p4_get_field h field) in

			let field_string = List.fold_left (fun s v ->
				List.fold_left (fun s val_or_mask ->
					let (unused, value, mask) = match val_or_mask with 
					| Value_or_masked_value (l, v) ->
						(l, string_of_int v, mask_of_bits bitwidth)
					| Value_or_masked_mask (l, v, m) ->
						(l, (string_of_int v), (string_of_int m))
					| Value_or_masked_name s ->
						raise(Failure "name not supported")
					in

					let header = String.uppercase header in
					let field = String.uppercase field in
					let goto = match snd v with
						| State_function n ->
							p4_lookup_extract_from_function n set
						| Parse_error n ->
							raise (Failure "parser_error not supported")
					in

					s
					^ "\t{\n"
					^ "\t\t.node = HEADER_INSTANCE_" ^ String.uppercase goto ^ ",\n"
					^ "\t\t.field = {\n" 
					^ "\t\t\t.header = " ^ "HEADER_" ^ String.uppercase h ^ ",\n" 
					^ "\t\t\t.field = HEADER_" ^ String.uppercase h ^ "_" ^ field ^ ",\n" 
					^ "\t\t\t.type = " ^ "NET_MAT_FIELD_REF_ATTR_TYPE_" ^ String.uppercase bitwidth ^ ",\n" 
					^ "\t\t\t.v." ^ bitwidth ^ " = {\n"
					^ "\t\t\t\t.value_" ^ bitwidth ^ " = " ^ value ^ ","
					^ "\n\t\t\t\t.mask_" ^ bitwidth ^ " = " ^ mask
					^ "\n\t\t\t}\n"
					^ "\t\t},\n"
					^ "\t},\n"
				) "" (fst v)
			) "" values in
			field_string
	in

	if (String.compare node "") == 0 then
		""
	else
		"static struct net_mat_jump_table " ^ node ^ "_jump[] = {\n" ^
	jump_table_fields ^
	"\t{ .node = 0, },\n" ^
	"};\n\n"

let _p4_parser_ref_match t p c =
	let node_defs = List.fold_left (fun s entry -> s ^ _p4_parser_match entry p) "" (List.rev p) in

	node_defs
