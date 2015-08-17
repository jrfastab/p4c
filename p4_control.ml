open P4_header
open P4_header_type
open P4_table

type p4_control_action =
	| Action_default
	| Action_hit
	| Action_miss
	| Action_name of string

type p4_control_bool_exp_un_op =
	| Control_bool_op_exp_un_op_tilda
	| Control_bool_op_exp_un_op_negate

type p4_control_bool_exp_bin_op =
	| Control_bool_expr_exp_bin_op_plus
	| Control_bool_expr_exp_bin_op_star
	| Control_bool_expr_exp_bin_op_minus
	| Control_bool_expr_exp_bin_op_lshift
	| Control_bool_expr_exp_bin_op_rshift
	| Control_bool_expr_exp_bin_op_land
	| Control_bool_expr_exp_bin_op_lor
	| Control_bool_expr_exp_bin_op_carrot

type p4_control_bool_op =
	| Control_bool_op_or
	| Control_bool_op_and

type p4_control_rel_op =
	| GreaterThan
	| GreaterThanOrEqual
	| Equal
	| LessThanOrEqual
	| LessThan
	| NotEqual

type p4_control_field_ref = {
	control_header : string;
	control_field : string;
}

type p4_control_bool_exp =
	| Control_bool_op_exp_exp of p4_control_bool_exp * p4_control_bool_exp_bin_op * p4_control_bool_exp
	| Control_bool_op_exp_un_op of p4_control_bool_exp_un_op * p4_control_bool_exp
	| Control_bool_op_exp_field of p4_control_field_ref
	| Control_bool_op_exp_value of int
	| Control_bool_op_exp_paren of p4_control_bool_exp

type p4_control_bool_expr =
	| Control_bool_header_ref of string
	| Control_bool_op_expr of p4_control_bool_expr * p4_control_bool_op * p4_control_bool_expr
	| Control_bool_op_not of p4_control_bool_expr
	| Control_bool_op_paren of p4_control_bool_expr
	| Control_bool_op_relop of p4_control_bool_exp * p4_control_rel_op * p4_control_bool_exp
	| Control_bool_op_true
	| Control_bool_op_false

type p4_control_ref = {
	control_ref : string;
	control_block : p4_control_statement list;
}

and p4_control_statement =
	| Apply_table_call of string 
	| Apply_and_select_block of p4_control_apply_and_select_block 
	| If_else_statement of p4_control_if_else_statement
	| Control_fn_name of string

and p4_control_apply_and_select_block = {
	control_table : string;
	control_case_list : p4_control_case_list;
}

and p4_control_case_list =
	| Action_case of p4_control_action_case list

and p4_control_action_case = {
	control_action : p4_control_action;
	control_action_block : p4_control_block;
}

and p4_control_block =
	| Action_control_block of p4_control_statement

and p4_control_if_else_statement = {
	bool_expr : p4_control_bool_expr;
	if_control_block : p4_control_block;
	else_block : p4_else_block option;
}

and p4_else_block =
	| Control_else_block of p4_control_block
	| Control_else_if_else_block of p4_control_if_else_statement

let p4_control : ((p4_control_ref list) ref) = ref []

let _p4_add_control b =
	p4_control := (b :: !p4_control)
