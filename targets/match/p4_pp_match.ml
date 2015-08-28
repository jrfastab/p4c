open P4_printer

module P4_Printer_Match : P4_Printer = struct
	let p4_pp_preamble = P4_primitives_match.p4_preamble_match
	let p4_pp_action ap a t p cntrs = P4_action_match.p4_action_ref_match ap a t p cntrs
	let p4_pp_header h = P4_header_match._p4_header_ref_match h
	let p4_pp_header_type ht = P4_header_type_match._p4_header_type_ref_match ht
	let p4_pp_parser t p c = P4_parser_match._p4_parser_ref_match t p c
	let p4_pp_table t p c a h = P4_table_match._p4_table_ref_match t p c a h
	let p4_pp_control c = P4_control_match._p4_control_ref_match c
end
