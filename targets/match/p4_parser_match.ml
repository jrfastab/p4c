open P4_parser
open P4_header_type

let _p4_parser_ref_p4 (x : p4_parser_ref) =
	"parser " ^ x.parser_ref ^ " {\n" ^
		  "}\n"

let _p4_parser_match (x : p4_parser_ref) =
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

	let _node = x.p4_parser.extract_or_set in
	let field = x.p4_parser.return in
	let xs = [] in

	let node = match _node with
		| Set x ->
			raise(Failure "metadata set not supported")
		| Extract x ->
			begin
			match x.index with
			| Some y ->
				raise(Failure "index not yet supported")
			| None ->
				String.uppercase x.instance
			end
	in

	let svalues = match field with
		| Value v -> 
			raise(Failure "unsupported value")
		| Select v ->
		let values = 
		List.fold_left (fun xs v ->
			let value_list = match v.value_list with
				| Value_or_masked l ->
					l	
				| Default ->
					raise(Failure "default not supported") 
			in
			(value_list, v.case_return_value) :: xs
		) xs v.case in
		let select =
			List.fold_left (fun s v ->
				match v with
				| Latest x -> (String.uppercase x) :: s
				| Current (x, y) ->
					raise(Failure "select current not supported")
				| Field_ref x -> (String.uppercase x) :: s
			) [] v.select in
		(select, values)	
	in

	let values = snd svalues in
	let select = fst svalues in
	let field = p4_get_field (String.lowercase node)
				 (String.lowercase (List.hd select)) in

	let bits = _p4_parser_field_to_bitwidth_str field in

	"static struct net_mat_jump_table " ^ x.parser_ref ^ "[] = {\n" ^

	List.fold_left (fun str (vs, r) ->
		List.fold_left (fun str v ->
			let (l, v, m) = 
				match v with 
				| Value_or_masked_value (l, v) ->
					(l, string_of_int v, mask_of_bits bits)
				| Value_or_masked_mask (l, v, m) ->
					(l, (string_of_int v), (string_of_int m))
				| Value_or_masked_name s ->
					raise(Failure "name not supported")
			in

			str ^"\t{\n\t\t.node = HEADER_INSTANCE_" ^ node ^ ",\n" 
			^ "\t\t.field = {\n" 
			^ "\t\t\t.header = " ^ "HEADER_" ^ node ^ ",\n" 
			^ "\t\t\t.field = " ^ "HEADER_" ^ node ^ "_" ^
				List.hd select ^ ",\n" 
			^ "\t\t\t.type = " ^ "NET_MAT_FIELD_REF_ATTR_TYPE" ^ ",\n" 
			^ "\t\t\tv.u " ^ "" ^ " = {\n"
			^ "\t\t\t\t.value_" ^ bits ^ " = " ^ v
			^ "\n\t\t\t\t.mask_" ^ bits ^ " = " ^ m
			^ "\n\t\t\t}\n\t\t}\n\t},\n"
		) str vs
	) "" values ^
	"\t{\n" ^
	"\t\t.node = 0,\n" ^
	"\t},\n" ^
	"};\n"

let _p4_parser_ref_match p =
	List.fold_left (fun s p -> s ^ _p4_parser_match p) "" p
