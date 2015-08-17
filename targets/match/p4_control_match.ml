open Batteries
open P4_control
open P4_table
open P4_header
open P4_header_type

let _p4_control_stmt_jump_table_entry_match str l =
	let _p4_print_apply x =
		"\t{ .field = {0}, .node = " ^ x ^ "},\n"
	in

	let _p4_print_rel_op_e e0 =
		match e0 with
		| Control_bool_op_exp_exp (e0, op, e1) ->
			begin
			match op with
			| Control_bool_expr_exp_bin_op_plus
			| Control_bool_expr_exp_bin_op_star
			| Control_bool_expr_exp_bin_op_minus
			| Control_bool_expr_exp_bin_op_lshift
			| Control_bool_expr_exp_bin_op_rshift
			| Control_bool_expr_exp_bin_op_lor
			| Control_bool_expr_exp_bin_op_carrot ->
				raise (Failure "op not supported")
			| Control_bool_expr_exp_bin_op_land ->
				begin
				match e0 with	
				| Control_bool_op_exp_field fref ->
					begin
					match e1 with
					| Control_bool_op_exp_value mask ->
						(Some fref, Some mask, None)
					| _ -> raise (Failure "expect field & `value`")
					end
				| Control_bool_op_exp_value mask  ->
					begin
					match e1 with
					| Control_bool_op_exp_field fref ->
						(Some fref, Some mask, None)
					| _ -> raise (Failure "expect field & `value`")
					end
				| _ -> raise (Failure "expect field & `value`")
				end
			end
		| Control_bool_op_exp_un_op (op, exp) ->
			raise (Failure "parens not supported\n")
		| Control_bool_op_exp_field fref ->
				(Some fref, None, None)
		| Control_bool_op_exp_value value  ->
				(None, None, Some value)
		| Control_bool_op_exp_paren x ->
			raise (Failure "parens not supported\n")
	in

	let _p4_print_rel_op e0 e1 =
		let (f1, m1, v1) = _p4_print_rel_op_e e0 in
		let (f2, m2, v2) = _p4_print_rel_op_e e1 in

		let f = match f1 with
		| Some f ->
			begin
			match f2 with
			| Some f2 -> raise (Failure "can not specify `field op field`")
			| None -> f
			end
		| None ->
			begin
			match f2 with
			| Some f -> f
			| None -> raise (Failure "can not specify `field op field`")
			end
		in

		let m = match m1 with
		| Some m ->
			begin
			match m2 with
			| Some m -> raise (Failure "can not specify multiple masks")
			| None -> m
			end
		| None ->
			begin
			match m2 with
			| Some m -> m
			| None -> 0 
			end
		in

		let v = match v1 with
		| Some v ->
			begin
			match v2 with
			| Some v -> raise (Failure "can not specify multiple values")
			| None -> v
			end
		| None ->
			begin
			match v2 with
			| Some v -> v
			| None -> raise (Failure "must specify some value");
			end
		in

		(f, m, v)
	in
		

	let _p4_print_if_else x =
		let (f, m, v) =
			match x.bool_expr with
			| Control_bool_header_ref x ->
				raise (Failure "not operation not supported\n")
			| Control_bool_op_expr (e0, op, e1) ->
				raise (Failure "not operation not supported\n")
			| Control_bool_op_not e0 ->
				raise (Failure "not operation not supported\n")
			| Control_bool_op_paren e0 ->
				raise (Failure "parens not supported\n")
			| Control_bool_op_relop (e0, relop, e1) ->
				begin
				match relop with
				| GreaterThan
				| GreaterThanOrEqual
				| LessThanOrEqual
				| LessThan
				| NotEqual ->
					raise (Failure "binary op not supprted\n")
				| Equal ->
					_p4_print_rel_op e0 e1
				end
			| Control_bool_op_true ->
				raise (Failure "true boolean stmt not supprted\n")
			| Control_bool_op_false ->
				raise (Failure "false boolean stmt not supprted\n")
		in

		let e =
			match x.if_control_block with
			| Action_control_block stmt ->
			(* The match-interface only supports a depth of 1 this
			   requires the next stmt to be an apply
			*)
				match stmt with
				| Apply_table_call x ->
					let t = p4_get_table x in
					x
		in

		let b = 
			match x.else_block with
			| Some block -> "TBD"
			| None -> ""
		in

		let instance = p4_get_instance_header f.header in
		let field = p4_get_field instance.header_ref f.field in

		let bitwidth = match field.bitwidth with
		| Int x when x < 9 -> "u8"
		| Int x when x < 17 -> "u16"
		| Int x when x < 33 -> "u32"
		| Int x when x < 65 -> "u64"
		| _ -> raise (Failure "invalid bitwidth")
		in
		
		"\t{ .field = {\n" ^
		"\t\t    .instance = HEADER_INSTANCE_" ^ String.uppercase f.header ^ ",\n" ^
		"\t\t    .header = HEADER_" ^ String.uppercase f.header ^ ",\n" ^
		"\t\t    .field = HEADER_"^ String.uppercase f.header ^ "_" ^ String.uppercase f.field ^ ",\n" ^
		"\t\t    .mask_type = NET_MAT_FIELD_REF_ATTR_TYPE_" ^ "" ^ ",\n" ^
		"\t\t    .type = NET_MAT_FIELD_REf_ATTR_TYPE_" ^ "" ^ ",\n" ^
		"\t\t    .v." ^ "" ^ " = {\n" ^
		"\t\t\t.value_" ^ "" ^ " = " ^ string_of_int v ^ ",\n" ^
		"\t\t\t.mask_u" ^ "" ^ " = " ^ string_of_int m ^ ",\n" ^
		"\t\t}},\n" ^
		"\t  .node = TABLE_" ^ String.uppercase e ^ "},\n"
	in
		
	match l with
	| [] -> str 
	| x :: xs ->
		begin
		match x with
		| Apply_table_call x ->
			let t = p4_get_table x in
			str ^ _p4_print_apply x 
		| Apply_and_select_block x -> str
		| If_else_statement x ->
			_p4_print_if_else x
		| Control_fn_name x -> "TBD"
		end

let _p4_control_stmt_jump_table_match str hd l =
	let name = 
		match hd with
		| Apply_table_call x -> let t = p4_get_table x in x
		| Apply_and_select_block x -> "TBD"
		| If_else_statement x -> "TBD"
		| Control_fn_name x -> "TBD"
	in

(*
	let next_str = match next with
	| Some n -> 
		"\t{ .field = {0}, .node = TABLE_" ^ n ^ "},\n"
	| None ->
		""
	in

	str ^
*)
	str ^
	"static struct net_mat_jump_table tbl_node_" ^ name ^ "_jump[] = {\n" ^
	_p4_control_stmt_jump_table_entry_match "" l
	^ "\t{ .field = {0}, .node = 0},\n" ^
	"};\n\n"

let _p4_control_stmt_declaration_apply_match str b =
	str ^
	"static struct net_mat_tbl_node table_node_" ^ b ^ " = {\n" ^
	"\t.uid = TABLE_" ^ String.uppercase b ^ ",\n" ^
	"\t.flags = 0,\n" ^
	"\t.jump = tbl_node_" ^ b ^ "_jump\n" ^
	"};\n"

let _p4_control_apply_and_select_match str b =
	str

let _p4_control_if_else_match str b =
	str

let _p4_control_stmt_declaration_match str hd =
	match hd with
	| Apply_table_call x -> _p4_control_stmt_declaration_apply_match str x
	| Apply_and_select_block x -> _p4_control_apply_and_select_match str x
	| If_else_statement x -> _p4_control_if_else_match str x
	| Control_fn_name x -> "TBD"

let rec _p4_control_stmt_match str b =
	match b with
	| [] -> str
	| hd::l ->
		_p4_control_stmt_jump_table_match str hd l ^
		_p4_control_stmt_declaration_match str hd ^
		_p4_control_stmt_match str l
(*
let _p4_control_stmt_match b =
	List.fold_left (fun str stmt ->
		match stmt with
		| Apply_table_call x -> _p4_control_apply_match str x None
		| Apply_and_select_block x -> _p4_control_apply_and_select_match str x
		| If_else_statement x -> _p4_control_if_else_match str x
		| Control_fn_name x -> "TBD"
	) "" b
*)

let _p4_control_match c =
	_p4_control_stmt_match "" c.control_block

let _p4_control_ref_match c =
	List.fold_left (fun s c -> s ^ _p4_control_match c) "" c
