open P4_printer
open P4_table
open P4_table_bpf
open P4_parser_bpf
open P4_primitives_bpf
open P4_actions_bpf

module P4_Printer_BPF : P4_Printer = struct
	let p4_pp_preamble = _p4_preamble_ebpf
	let p4_pp_action ap a t p cntrs = _p4_primitive_action_ref_bpf ap a t p cntrs
	let p4_pp_header h = ""
	let p4_pp_header_type ht = ""
	let p4_pp_table t p c a = _p4_table_ref_ebpf t p c a
	let p4_pp_parser t p = _p4_parser_ref_ebpf t p
	let p4_pp_control c = ""
end
