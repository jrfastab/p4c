open Batteries
open P4_header_type

type p4_parser_extract_index =
	| Next
	| Index of int

type p4_parser_extract = {
	instance : string;
	index : p4_parser_extract_index option;
}

type p4_parser_field_ref = 
	| Current of int * int
	| Latest of string
	| Field_ref of string

type p4_parser_metadata_expr =
	| Field_value of int
	| Field_md_ref of p4_parser_field_ref

type p4_parser_set = {
	field_ref : string;
	metadata_expr : p4_parser_metadata_expr;
}

type p4_parser_extract_or_set =
	| Extract of p4_parser_extract
	| Set of p4_parser_set

type p4_parser_return_value =
	| State_function of string
	| Parse_error of string

type p4_parser_value_or_masked =
	| Value_or_masked_value of int * int
	| Value_or_masked_mask of int * int * int
	| Value_or_masked_name of string

type p4_parser_value =
	| Value_or_masked of p4_parser_value_or_masked list
	| Default

type p4_parser_case =  {
	value_list : p4_parser_value;
	case_return_value : p4_parser_return_value;
}

type p4_parser_select = {
	select : p4_parser_field_ref list;
	case : p4_parser_case list;
}

type p4_parser_return =
	| Value of p4_parser_return_value
	| Select of p4_parser_select

type p4_parser = {
	extract_or_set : p4_parser_extract_or_set option;
	return : p4_parser_return;
}

type p4_parser_ref = {
	parser_ref : string;
	p4_parser : p4_parser;
}

let p4_parser : ((p4_parser_ref list) ref) = ref []

let p4_add_parser_type_ref p =
	p4_parser := (p :: !p4_parser)
