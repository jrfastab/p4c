open P4_action

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
struct count {
	unsigned long packets;
	unsigned long bytes;
};

static inline int p4_count_action_intrinsic(counter_t counter, uint32_t index, const struct __sk_buff *skb)
{
	struct count *cnt, _cnt;

	cnt = p4_map_lookup_elem(bpf_map_ptrs[counter], &index);

	if (cnt) {
		__sync_fetch_and_add(&cnt->packets, 1);
		__sync_fetch_and_add(&cnt->bytes, skb->len);
	} else {
		_cnt.packets = 1;
		_cnt.bytes = skb->len;
		p4_map_update_elem(bpf_map_ptrs[counter], &index, &_cnt, BPF_ANY);
	}

	return 0;
}
"

let p4_actions_bpf_modify =
"
static inline int p4_modify_action_intrinsic(uint32_t header, uint32_t field, *value, const struct __sk_buff *skb)
{

}
"

let p4_actions_bpf_codes actions =
	let codes = List.fold_left (fun s a ->
		s ^ "\tBPF_P4_ACTION_" ^ (String.uppercase a.p4_action_ref) ^ ",\n"
	) "" actions in

	"enum {\n" ^
	codes ^
	"};\n\n"

let p4_actions_bpf_intrinsics =
	("drop", p4_actions_bpf_drop) ::
	("count", p4_actions_bpf_count) ::
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
	"struct p4_action_value {\n" ^
	"\t__u8 action_code;\n" ^
	"\tunion {\n" ^
	(List.fold_left (fun s a ->
		match (List.hd a.p4_actions_args) with
		| P4_Action_Arg_Void_T -> s
		| _ ->
			s ^ "\t\tstruct p4_table_act_" ^ a.p4_action_ref ^ " " ^ a.p4_action_ref ^ ";\n"
	) "" actions) ^
	"\t};\n" ^
	"};\n\n"

let p4_action_function_get_args args =
	List.map (fun arg ->
		match arg with
		| P4_Action_Arg_Void_T ->
			None
		| P4_Action_Arg_Header_T s ->
			Some ("header_t " ^ s)
		| P4_Action_Arg_Field_T s ->
			Some ("field_t " ^ s)
		| P4_Action_Arg_Value_T s ->
			Some ("value_t " ^ s)
		| P4_Action_Arg_Mask_T s ->
			Some ("mask_t " ^ s)
		| P4_Action_Arg_Counter_T s ->
			Some ("counter_t " ^ s)
		| P4_Action_Arg_Packet_T s ->
			Some ("struct __sk_buff *" ^ s)
	) args

let p4_action_to_struct action =
	let action_args = p4_action_function_get_args action.p4_actions_args in

	if (List.hd action_args) == None then
		""
	else
		"struct p4_table_act_" ^ action.p4_action_ref ^ " {\n" ^
		(List.fold_left (fun s a ->
			s ^ (match a with | Some s -> "\t" ^ s ^ ";\n" | None -> "")) "" action_args) ^
		"};\n\n"

let p4_action_value_structs actions =
	let act_spec = List.fold_left (fun s a ->
		s ^ (p4_action_to_struct a)
	) "" actions
	in

	act_spec

let p4_action_eval_args ref actions =
	let act = List.find (fun a ->
		if (String.compare ref a.p4_action_ref) == 0 then true else false	
	) actions in

	let args = List.mapi (fun i arg ->
		begin
		match arg with
		| P4_Action_Arg_Void_T -> ""
		| P4_Action_Arg_Header_T s ->
			"value->" ^ act.p4_action_ref ^ "." ^ s
		| P4_Action_Arg_Field_T s ->
			"value->" ^ act.p4_action_ref ^ "." ^ s
		| P4_Action_Arg_Value_T s ->
			"value->" ^ act.p4_action_ref ^ "." ^ s
		| P4_Action_Arg_Mask_T s ->
			"value->" ^ act.p4_action_ref ^ "." ^ s
		| P4_Action_Arg_Counter_T s ->
			"value->" ^ act.p4_action_ref ^ "." ^ s
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
		"\t\tout = p4_" ^ a.p4_action_ref ^ "_action(" ^ p4_action_eval_args a.p4_action_ref actions  ^ ");\n" ^
		"\t\tbreak;\n"
	) "" actions
	in

	"static inline int p4_eval_action(struct p4_action_value *value, struct __sk_buff *skb)\n" ^
	"{\n" ^
		"\tint out;\n\n" ^
		"\tswitch (value->action_code) {\n" ^
		switch_cases ^
		"\t};\n\n" ^
		"\treturn out;\n" ^
	"}\n\n"

let p4_action_function_args action =
	let args = p4_action_function_get_args action.p4_actions_args in
	let args_r = List.map (fun a -> (match a with | Some s -> s | None -> "")) args in

	let args_comma = List.mapi (fun i arg ->
		arg ^ (if (i + 1 < List.length args) then ", " else "")
	) args_r in

	List.fold_left (fun s arg ->
		s ^ arg	
	) "" args_comma

let p4_action_function_stmts action =
	let args stmt = match stmt.p4_action_stmt_args with
		| None -> ""
		| Some args ->
			let argmap =
			List.mapi (fun i arg ->
				arg ^
				(if (i + 1 < List.length args) then ", " else "")
			) args in

			List.fold_left (fun s a -> s ^ a) "" argmap
	in

	match action.p4_actions_stmts with
	| None -> "" 
	| Some stmts ->
		List.fold_left (fun s stmt ->
			s ^
			"\tout = p4_" ^ stmt.p4_action_stmt ^ "_action_intrinsic(" ^ (args stmt) ^ ");\n"
		) "" stmts

let p4_action_functions actions =
	List.fold_left (fun s action ->
		s ^
		"static inline int p4_" ^ action.p4_action_ref ^ "_action(" ^ p4_action_function_args action ^ ")\n" ^
		"{\n" ^
			"\tint out;\n\n" ^
			(p4_action_function_stmts action) ^
			"\treturn out;\n" ^
		"}\n\n"
	) "" actions

let _p4_primitive_action_ref_bpf actions_primitive actions =
	let primitives = p4_primitive_action_bpf actions_primitive in
	let action_calls = p4_action_functions actions in
	let codes = p4_actions_bpf_codes actions in
	let action_value = p4_action_value actions in
	let action_structs = p4_action_value_structs actions in
	let eval_action = p4_action_eval actions in

	p4_actions_bpf_types ^ primitives ^ action_calls ^ codes ^ action_structs ^ action_value ^ eval_action
