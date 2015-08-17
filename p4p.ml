type p4_extract_index =
	| Int of int
	| Next

type p4_extract_stmt = {
	instance : string;
	index : p4_extract_index option;
}

type p4_metadata_expr =
	| Set_stmt_metadata_expr_value of int 
	| Set_stmt_metadata_expr_ref of string

type p4_set_stmt =
	| Set_stmt of string * p4_metadata_expr

type p4_return_stmt_value_type =
	| Return_stmt_value_type_state of string
	| Return_stmt_value_type_function of string
	| Return_stmt_value_type_error of string

type p4_return_stmt_select_field_or_data_ref =
	| Return_stmt_select_field_or_data_ref_field of string
	| Return_stmt_select_field_or_data_ref_latest of string
	| Return_stmt_select_field_or_data_ref_current of int * int

type p4_return_stmt_select_exr = {
	p4_return_stmt_select_expr_field_or_data_ref : p4_return_stmt_select_field_or_data_ref
}

type p4_return_stmt_case = {

}

type p4_return_stmt = {
	| Return_stmt_value of p4_return_stmt_value_type
	| Return_stmt_select of p4_return_stmt_select_expr * p4_return_stmt_case list
}

type p4_parser_body = {
	extract : p4_extract_stmt option list;
	set_stmts : p4_set_stmt option list;
	return_stmts : p4_return_stmt option list;	
}

type p4_parser_ref = {
	ref : string;
	p4p : p4_parser_body;
} 
