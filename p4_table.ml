open P4_header
open P4_header_type

type p4_field_or_masked_ref =
	| Field_ref_header of string
	| Field_ref_field of string * string
	| Field_ref_mask of string * string * int

type p4_field_match_type =
	| Field_match_type_exact
	| Field_match_type_ternary
	| Field_match_type_lpm
	| Field_match_type_range
	| Field_match_type_valid

type p4_table_reads = {
	field_or_masked_ref : p4_field_or_masked_ref;
	field_match_type : p4_field_match_type;
}

type p4_table_action =
	| Table_action_spec of string list
	| Table_action_profile of string

type p4_table = {
	reads : p4_table_reads list option;
	table_actions : p4_table_action;
	min_size : int option;
	max_size : int option;
	size : int option;
	support_timeout : bool option;
}

type p4_table_ref = {
	table_ref : string;
	p4_table : p4_table;
}

(* P4 Table routines *)
let p4_tables : ((p4_table_ref list) ref) = ref []

let p4_get_table name =
	let is_table t =
		if ((String.compare t.table_ref name) == 0) then true else false
	in
	List.find (is_table) !p4_tables

let p4_add_table t =
	p4_tables := (t :: !p4_tables)
