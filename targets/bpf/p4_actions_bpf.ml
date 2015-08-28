open P4_action
open P4_header
open P4_header_type
open P4_counters

(* Track the header modify keys needed from parser *)
let p4_header_mods : ((string list) ref) = ref []
let p4_add_header_mod h = p4_header_mods := (h :: !p4_header_mods)

let p4_actions_bpf_types =
"
struct field_value {
	uint32_t header;
	uint32_t field;
};

typedef uint32_t header_t;
typedef struct field_value field_t;
typedef uint32_t value_t;
typedef void* mask_t;
typedef uint32_t counter_t;
typedef struct __sk_buff skb;
"

let p4_actions_bpf_drop =
"
static inline int p4_drop_action_intrinsic(void)
{
	return TC_ACT_SHOT;	
}\n
"

let p4_actions_bpf_count =
"
static inline int p4_count_action_intrinsic(struct bpf_elf_map *map, uint32_t index, const struct __sk_buff *skb)
{
	struct count *cnt, _cnt;

	cnt = p4_map_lookup_elem(map, &index);

	if (cnt) {
		__sync_fetch_and_add(&cnt->packets, 1);
		__sync_fetch_and_add(&cnt->bytes, skb->len);
	} else {
		_cnt.packets = 1;
		_cnt.bytes = skb->len;
		p4_map_update_elem(map, &index, &_cnt, BPF_ANY);
	}

	return 0;
}
"

let p4_actions_bpf_modify =
"
static inline int p4_modify_action_intrinsic_u8(__u8 src, __u8 *dst)
{
  *dst = src;
  return 0;
}

static inline int p4_modify_action_intrinsic_u16(__u16 src, __u16 *dst)
{
  *dst = src;
  return 0;
}

static inline int p4_modify_action_intrinsic_u32(__u32 src, __u32 *dst)
{
  *dst = src;
  return 0;
}

static inline int p4_modify_action_intrinsic_u64(__u64 src, __u64 *dst)
{
  *dst = src;
  return 0;
}

static inline int p4_modify_mdata_action_intrinsic(__u8 *src,
                                                    __u8 *dst,
                                                    uint32_t len)
{
  memcpy(src, dst, len);
  return 0;
}
"

let p4_actions_bpf_codes actions =
	let codes = List.fold_left (fun s a ->
		s ^ "\tBPF_P4_ACTION_" ^ (String.uppercase a.p4_action_ref) ^ ",\n"
	) "" actions in

	"enum {\n" ^
	"\tBPF_P4_ACTION_UNSPEC,\n" ^
	codes ^
	"};\n\n"

let p4_actions_bpf_intrinsics =
	("drop", p4_actions_bpf_drop) ::
	("count", p4_actions_bpf_count) ::
 	("modify", p4_actions_bpf_modify) ::
	[]

let p4_actions_bpf_instrinsic_map str =
	let map = p4_actions_bpf_intrinsics in	
	let tuple = List.find (fun a ->
		if (String.compare (fst a) str) == 0 then true else false
	) map in

	snd tuple


let p4_primitive_action_bpf (actions : p4_action_primitive_ref list) =
	List.fold_left (fun s a ->
		s ^ (p4_actions_bpf_instrinsic_map a.p4_action_primitive_ref)
	) "" actions

let p4_action_value actions =
	"struct __attribute__ ((__packed__)) p4_action_value {\n" ^
	"\t__u32 action_code;\n" ^
	"\tunion {\n" ^
	(List.fold_left (fun s a ->
		match (List.hd a.p4_actions_args) with
		| P4_Action_Arg_Void_T -> s
		| _ ->
			s ^ "\t\tstruct p4_table_act_" ^ a.p4_action_ref ^ " " ^ a.p4_action_ref ^ ";\n"
	) "" actions) ^
	"\t};\n" ^
	"};\n\n"

let p4_action_function_arg_unwind_value s action =
  (* TBD add catch for unused values *)
  let find_arg arglist = List.find(
    fun arg ->
      if (String.compare s arg) == 0 then true else false
  ) arglist in

  let find_arg_in_stmt_list stmt_list =
     List.find (fun stmt ->
                match stmt.p4_action_stmt_args with
                | Some args -> 
                    let _obj = find_arg args in
                    true
                | None -> false
     ) stmt_list 
  in
 
  let stmt = match action.p4_actions_stmts with
  | Some stmts -> find_arg_in_stmt_list stmts
  | None ->
      let errstr = "Unused variable " ^ s ^ "\n" in
      raise(Failure errstr)
  in

  if (String.compare stmt.p4_action_stmt "modify") == 0 then
	begin
	let modfield = match stmt.p4_action_stmt_args with
		| Some args -> List.hd (List.rev args)
		| None -> raise (Failure "invalid modify field") in
	let h_f = Str.split (Str.regexp_string "_") modfield in
	let h = p4_get_instance_header (List.hd h_f) in
         
	let f = p4_get_field h.header_ref (List.hd (List.rev (h_f))) in
          
	begin
	match f.bitwidth with
	| Int w ->
		begin match w with
		| w when w <= 8 -> "__u8 " ^ s
		| w when w <= 16 -> "__u16 " ^ s
		| w when w <= 32 -> "__u32 " ^ s
		| w when w <= 64 -> "__u64 " ^ s
		| w ->
                  raise (Failure "bit length too large... unsupporte suffix\n")
		end
	| Unknown ->
		raise (Failure "bit length unknown... unsupporte suffix\n")
	end
	end
  else
    "uint32_t " ^ s

let p4_action_function_get_args action =
  let args = action.p4_actions_args in
	List.map (fun arg ->
		match arg with
		| P4_Action_Arg_Void_T ->
			None
		| P4_Action_Arg_Header_T s ->
			Some ("header_t " ^ s)
		| P4_Action_Arg_Field_T s ->
 		       Some ("field_t " ^ s)
		| P4_Action_Arg_Value_T s ->
      			Some (p4_action_function_arg_unwind_value s action)
		| P4_Action_Arg_Mask_T s ->
			Some ("mask_t " ^ s)
		| P4_Action_Arg_Counter_T s ->
			Some ("counter_t " ^ s)
		| P4_Action_Arg_Packet_T s ->
			Some ("struct __sk_buff *" ^ s)
		| P4_Action_Arg_KeyField_T (header, field) ->
			Some ("struct p4_extract_flow_keys *" ^ header ^ "_" ^ field)
	) args

let p4_action_to_struct action =
	let action_args = p4_action_function_get_args action in

	if (List.hd action_args) == None then
		""
	else
		"struct __attribute__ ((__packed__)) p4_table_act_" ^ action.p4_action_ref ^ " {\n" ^
		(List.fold_left (fun s a ->
			s ^ (match a with | Some s -> "\t" ^ s ^ ";\n" | None -> "")) "" action_args) ^
		"};\n\n"

let p4_action_to_mode_header_field stmt_args =
	match stmt_args with
	| Some args ->
		let mod_field = List.nth args 1 in
		(* TBD ugly _ split to fake out type *)
		let h_f = Str.split (Str.regexp_string "_") mod_field in
		let h = p4_get_instance_header (List.hd h_f) in
		let f = p4_get_field h.header_ref (List.hd (List.rev (h_f))) in

		(h, f)
	| None ->
		raise (Failure "malformed modify action!")

let p4_action_to_mod action =
	match action.p4_actions_stmts with
	| Some stmts -> 
		begin
		List.fold_left (fun s stmt ->
			if (String.compare stmt.p4_action_stmt "modify") == 0 then
				let (h, f) = p4_action_to_mode_header_field stmt.p4_action_stmt_args in

				let decl = try
					let exists = List.find (fun header ->
						if (String.compare (header) h.header_instance_name) == 0 then true else false
					) !p4_header_mods  in
					""
				with | Not_found ->
					begin
					p4_add_header_mod h.header_instance_name;
					"\tint " ^ h.header_instance_name ^ ";\n"
					end
				in
				decl
			else
				""
		) "" stmts
		end
	| None -> ""

let p4_action_value_structs actions =
	let act_spec = List.fold_left (fun s a ->
		s ^ (p4_action_to_struct a)
	) "" actions
	in

	let act_modify_ptr' = List.fold_left (fun s a -> s ^ (p4_action_to_mod a)) "" actions in
	let act_modify_ptr = "struct p4_header_ptrs_t {\n" ^ act_modify_ptr' ^ "};\n" in

	act_spec ^ act_modify_ptr

let p4_action_eval_args ref actions =
	let act = List.find (fun a ->
		if (String.compare ref a.p4_action_ref) == 0 then true else false	
	) actions in

	let key = match act.p4_actions_stmts with
		| Some stmts -> 
			List.fold_left (fun s stmt ->
				if (String.compare stmt.p4_action_stmt "modify") == 0 then ", key, headers, skb" else ""
			) "" stmts
		| None -> ""
	in

	let args = List.mapi (fun i arg ->
		begin
		match arg with
		| P4_Action_Arg_Void_T -> "";
		| P4_Action_Arg_Header_T s ->
			"value->" ^ act.p4_action_ref ^ "." ^ s ^ key
		| P4_Action_Arg_Field_T s ->
			"value->" ^ act.p4_action_ref ^ "." ^ s ^ key
		| P4_Action_Arg_Value_T s ->
			"value->" ^ act.p4_action_ref ^ "." ^ s ^ key
		| P4_Action_Arg_Mask_T s ->
			"value->" ^ act.p4_action_ref ^ "." ^ s ^ key
		| P4_Action_Arg_Counter_T s ->
			"value->" ^ act.p4_action_ref ^ "." ^ s ^ key
		| P4_Action_Arg_KeyField_T (header, field) ->
 			"key->"  ^ header ^ "_" ^ field 
		| P4_Action_Arg_Packet_T s ->
			s
		end
		^ (if (i + 1 < List.length act.p4_actions_args) then ", " else "")
	 ) act.p4_actions_args in

	List.fold_left (fun s arg -> s ^ arg) "" args

let p4_action_eval actions =
	let switch_cases = List.fold_left (fun s a ->
		s ^
		"\tcase BPF_P4_ACTION_" ^ (String.uppercase a.p4_action_ref) ^ ":\n" ^
		"\t\tout = p4_" ^ a.p4_action_ref ^ "_action(" ^ (p4_action_eval_args a.p4_action_ref actions)  ^ ");\n" ^
		"\t\tbreak;\n"
	) "" actions
	in

	"static inline int p4_eval_action(struct p4_extract_flow_keys *key, struct p4_header_ptrs_t *headers, struct p4_action_value *value, struct __sk_buff *skb)\n" ^
	"{\n" ^
		"\tint out;\n\n" ^
		"\tswitch (value->action_code) {\n" ^
		switch_cases ^
		"\t};\n\n" ^
		"\treturn out;\n" ^
	"}\n\n"

let p4_action_function_args stmts action =
	let args = p4_action_function_get_args action in
	let args_r = List.map (fun a -> (match a with | Some s -> s | None -> "")) args in
	let suffix = List.fold_left (fun s (suffix, preamble, stmt) ->
		s ^ suffix ^
		(if (String.compare (suffix) "") == 0 then "" else " ")
	) "" stmts in

	let key = if (String.compare suffix "") == 0 then "" else ", struct p4_extract_flow_keys *key, struct p4_header_ptrs_t *headers, struct __sk_buff *skb" in

	let args_comma = List.mapi (fun i arg ->
		arg ^ (if (i + 1 < List.length args) then ", " else "") ^ key
	) args_r in

	List.fold_left (fun s arg ->
		s ^ arg	
	) "" args_comma

let p4_action_counter_switch_block arg cntrs =
	"\tswitch (" ^ arg ^ ") {\n" ^
	(List.fold_left(fun s c ->
		s ^
		"\tcase BPF_P4_MAP_" ^ (String.uppercase c.counter_ref) ^ ":\n" ^
		"\t\tmap = &map_" ^ c.counter_ref ^ ";\n" ^
		"\t\tbreak;\n"
	) "" cntrs) ^
	"\t};\n"

let p4_action_function_stmts action primitives cntrs =
  let p4_action_stmt_get_primitive stmt =
    List.find (fun p ->
      stmt.p4_action_stmt;
        if (String.compare p.p4_action_primitive_ref stmt.p4_action_stmt) == 0
         then true
         else false
    ) primitives
  in

  let p4_action_arg_xlate arg i stmt =
    let primitive = p4_action_stmt_get_primitive stmt in

    match List.nth primitive.p4_action_primitive i with
    | P4_Action_Arg_Void_T -> arg
    | P4_Action_Arg_Field_T s
    | P4_Action_Arg_Header_T s
    | P4_Action_Arg_Value_T s
    | P4_Action_Arg_Mask_T s
    | P4_Action_Arg_Packet_T  s -> arg
    | P4_Action_Arg_Counter_T s -> "map"
    | P4_Action_Arg_KeyField_T (header, field) ->
        "&key->" ^ arg 
  in

  let p4_action_arg_build_suffix arg stmt =
    let primitive = p4_action_stmt_get_primitive stmt in

    if (String.compare stmt.p4_action_stmt "modify") == 0 then

    match stmt.p4_action_stmt_args with
    | Some args ->
       begin
         let mod_field = List.nth args 1 in
         (* TBD ugly _ split to fake out type *)
         let h_f = Str.split (Str.regexp_string "_") mod_field in
         let h = p4_get_instance_header (List.hd h_f) in
         let f = p4_get_field h.header_ref (List.hd (List.rev (h_f))) in

          begin
          match f.bitwidth with
          | Int w ->
              begin match w with
              | w when w <= 8 ->
                   "_u8"
              | w when w <= 16 ->
                   "_u16"
              | w when w <= 32 ->
                   "_u32"
              | w when w <= 64 ->
                   "_u64"
              | w ->
                  raise (Failure "bit length too large... unsupporte suffix\n")
              end
          | Unknown ->
                  raise (Failure "bit length unknown... unsupporte suffix\n")
          end
       end
    | None ->
        raise (Failure "invoke undefined modify action")
    else
        ""
  in

	let args stmt action = match stmt.p4_action_stmt_args with
		| None -> ("", [])
		| Some args ->
      			let suffix = p4_action_arg_build_suffix args stmt in
			let argmap = List.mapi (fun i arg ->
        			(p4_action_arg_xlate arg i stmt) ^
				(if (i + 1 < List.length args) then ", " else "")
			) args in

			(suffix, argmap)
	in

	let prestmt arg stmt =
		if (String.compare stmt.p4_action_stmt "count") == 0 then
			p4_action_counter_switch_block arg cntrs
		else
			""
	in

	match action.p4_actions_stmts with
	| None -> [] 
	| Some stmts ->
		List.map (fun stmt ->
      			let (suffix, args_list') = args stmt action in
			let preamble = prestmt (match stmt.p4_action_stmt_args with |Some args -> List.hd args |None -> "") stmt in
			let modify_stmt =
				if (String.compare "modify" stmt.p4_action_stmt) == 0 then
					let arg = match stmt.p4_action_stmt_args with | Some l -> l | None -> "" :: [] in
					let (keyh, keyf) =
						(let t = (Str.split (Str.regexp_string "_") (List.hd (List.rev arg))) in
						(List.hd t, List.hd (List.tl t))) in
					let offset = "headers->" ^ keyh in
					let field = p4_get_instance_field keyh keyf in
					let offheader = match field.offset_from_header with
						| Int x -> x
						| Unknown -> 0
					in
					let field_bytes = match field.bitwidth with
						| Int x -> string_of_int (x / 8)
						| Unknown -> "0"
					in

					"\tp4_skb_store_bytes(skb, " ^ offset ^ " + " ^ (string_of_int offheader)  ^ ", &" ^ (List.hd arg) ^ ", " ^ field_bytes ^ ", true);\n"
				else
					""
			in

			let args_list = List.fold_left (fun s a -> s ^ a) "" args_list' in

			(suffix, preamble,
			"\tout = p4_" ^ stmt.p4_action_stmt ^ "_action_intrinsic" ^
			suffix ^ "(" ^ args_list ^ ");\n" ^ modify_stmt)
		) stmts

let p4_action_functions actions primitives cntrs =
	List.fold_left (fun s action ->
		let stmts = (p4_action_function_stmts action primitives cntrs) in
		s ^
		"static inline int p4_" ^ action.p4_action_ref ^ "_action(" ^
    		(p4_action_function_args stmts action) ^ ")\n" ^
		"{\n" ^
			"\tint out;\n" ^
			"\tstruct bpf_elf_map *map;\n\n" ^
			(List.fold_left(fun s (suffix, preamble, stmt) -> s ^ preamble ^ stmt) "" stmts) ^
			"\treturn out;\n" ^
		"}\n\n"
	) "" actions

let _p4_primitive_action_ref_bpf actions_primitive actions tables p cntrs =
	let primitives = p4_primitive_action_bpf actions_primitive in
	let action_calls = p4_action_functions actions actions_primitive cntrs in
	let codes = p4_actions_bpf_codes actions in
	let action_value = p4_action_value actions in
	let action_structs = p4_action_value_structs actions in
	let key_structs = P4_table_bpf._p4_table_flow_key_bpf_elf tables p in
	let ebpf_cntrs = P4_table_bpf._p4_table_cntrs tables cntrs in
	let ebpf_enum = P4_table_bpf._p4_table_map_enum_bpf_elf tables cntrs in
	let ebpf_map = P4_table_bpf._p4_table_map_bpf_elf tables in
	let eval_action = p4_action_eval actions in

	p4_actions_bpf_types ^ codes ^
	action_structs ^ action_value ^
	key_structs ^ ebpf_enum ^ ebpf_map ^ ebpf_cntrs ^ 
	primitives ^ action_calls ^ eval_action
