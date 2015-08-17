open P4_header
open P4_header_type
open P4_parser
open P4_table
open P4_control
open P4_action

module type P4_Printer = sig
	val p4_pp_preamble : string
	val p4_pp_action : P4_action.p4_action_primitive_ref list -> P4_action.p4_action_ref list -> string
	val p4_pp_header : P4_header.p4_header_ref list -> string
	val p4_pp_header_type : P4_header_type.p4_header_type_ref list -> string
	val p4_pp_table : P4_table.p4_table_ref list -> P4_parser.p4_parser_ref list ->
			  P4_counters.p4_counter list ->  P4_action.p4_action_ref list -> string
	val p4_pp_parser : P4_table.p4_table_ref list -> P4_parser.p4_parser_ref list ->
			   P4_control.p4_control_ref list -> string
	val p4_pp_control : P4_control.p4_control_ref list -> string
end

module type P4_pp_printer = sig
	val pp_preamble : string
	val pp_action : P4_action.p4_action_primitive_ref list -> P4_action.p4_action_ref list -> string
	val pp_header_type : P4_header_type.p4_header_type_ref list -> string
	val pp_header : P4_header.p4_header_ref list -> string
	val pp_table : P4_table.p4_table_ref list -> P4_parser.p4_parser_ref list ->
		       P4_counters.p4_counter list -> P4_action.p4_action_ref list -> string
	val pp_parser : P4_table.p4_table_ref list -> P4_parser.p4_parser_ref list ->
			P4_control.p4_control_ref list -> string
	val pp_control : P4_control.p4_control_ref list -> string
	val pp : P4_counters.p4_counter list ->
		 P4_action.p4_action_primitive_ref list ->
		 P4_header_type.p4_header_type_ref list ->
		 P4_header.p4_header_ref list ->
		 P4_table.p4_table_ref list ->
		 P4_parser.p4_parser_ref list ->
		 P4_control.p4_control_ref list ->
		 P4_action.p4_action_ref list -> string
end

module Make_Printer(P : P4_Printer) : P4_pp_printer = struct
	let pp_preamble = P.p4_pp_preamble
	let pp_action a = P.p4_pp_action a
	let pp_header_type ht = P.p4_pp_header_type ht
 	let pp_header h = P.p4_pp_header h
	let pp_table t = P.p4_pp_table t
	let pp_parser t p c = P.p4_pp_parser t p c
	let pp_control c = P.p4_pp_control c

	let pp cntrs a ht h t p c acts =
		let ps = pp_preamble in
		let pa = pp_action a acts in
		let pht = (pp_header_type ht) in
		let ph = (pp_header h) in
		let pt = (pp_table t p cntrs acts) in
		let pp = (pp_parser t p c) in
		let pc = (pp_control c) in

		ps ^ pa ^ pht ^ pt ^ pp ^ pc
end
