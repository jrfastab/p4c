(*
let _p4_table_extract_instance i =
	let extract_print h f =
		let off = match f.offset_from_header with
			| Int x -> x
			| Unknown -> raise (Failure "unknown lengths unsupported")
		in

		"static inline p4_extract_" ^ h ^ "_" ^ f.field ^ "(" ^
			"struct __sk_buff *skb, int off)\n" ^
		"{\n" ^
		begin
		match f.bitwidth with
		| Int w ->
			begin
			match w with
			| w when w <= 8 ->
				"\t" ^
				(_p4_ebpf_primitive_mvu8 "dst" "skb" (string_of_int off)) ^
				"\n"
			| w when w <= 16 ->
				"\t" ^
				(_p4_ebpf_primitive_mvu16 "dst" "skb" (string_of_int off)) ^
				"\n"
			| w when w <= 32 ->
				"\t" ^
				(_p4_ebpf_primitive_mvu32 "dst" "skb" (string_of_int off)) ^
				"\n"
			| w when w <= 64 ->
				""
			| w ->
				raise (Failure "bit length too large... unsupported\n")
			end
		| Unknown -> ""
		end
		^ "}\n"
	in

	match i.field_or_masked_ref with 
	| Field_ref_header h ->
		""
	| Field_ref_field (h, f) ->
		let inst = p4_get_instance_header h in
		let field = p4_get_field inst.header_ref f in

		extract_print h field
	| Field_ref_mask (h, f, m) ->
		""

let _p4_table_extract_instances (table : p4_table_ref) =
	let t = table.p4_table in 

	match t.reads with
	| None -> ""
	| Some r ->
		List.fold_left (fun s i -> 
			s ^ (_p4_table_extract_instance i)
		) "" r

let _p4_table_extract_bpf_elf (t : p4_table_ref list) =
	List.fold_left (fun s t -> s ^ _p4_table_extract_instances t) "" (List.rev t)
*)

let _p4_header_ref_ebpf headers =
	let ebpf_extract = _p4_header_extract_bpf_elf headers in

	ebpf_extract
