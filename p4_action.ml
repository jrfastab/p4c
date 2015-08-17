type p4_action_primitive_argument_type =
	| P4_Action_Arg_Void_T
	| P4_Action_Arg_Header_T of string
	| P4_Action_Arg_Field_T of string
	| P4_Action_Arg_Value_T of string
	| P4_Action_Arg_Mask_T of string
	| P4_Action_Arg_Counter_T of string
	| P4_Action_Arg_Packet_T of string

type p4_action_primitive_ref = {
	p4_action_primitive_ref : string;
	p4_action_primitive : p4_action_primitive_argument_type list;
}

type p4_action_stmts = {
	p4_action_stmt : string;
	p4_action_stmt_args : string list option;
}

type p4_action_ref = {
	p4_action_ref : string;
	p4_actions_args : p4_action_primitive_argument_type list;
	p4_actions_stmts : p4_action_stmts list option;
}

let p4_action_primitives : ((p4_action_primitive_ref list) ref) = ref []

let _p4_add_action_primitive_type_ref a =
	p4_action_primitives := (a :: !p4_action_primitives)

let p4_actions : ((p4_action_ref list) ref) = ref []

let _p4_add_action_ref a =
	p4_actions := (a :: !p4_actions)


