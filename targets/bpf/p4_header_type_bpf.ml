open P4_header_type

let _p4_field_type_ebpf_to_string bits =
	match bits with
	| Int x ->
		begin
		match x with
		| x when (x <= 8) -> "__u8"
		| x when (x <= 16) -> "__u16"
		| x when (x <= 32) -> "__u32"
		| x when (x <= 64) -> "__u64"
		| x -> raise (Failure "bitwidth > __u64 not supported\n")
		end
	| Unknown -> raise (Failure "not supported yet")

let rec hex_of_ones' x set =
	if set > 0 then
		hex_of_ones' (x lor (1 lsl set)) (set - 1)
	else
		(x lor (1 lsl set))

let hex_of_ones set =
	hex_of_ones' 0 (set - 1)

let _p4_field_type_prim_load t bits =
	match bits with
	| Int x ->
		begin
		match x with
		| x when (x <= 8) -> "p4_ebpf_load_bytes(skb, src) & " ^ string_of_int (hex_of_ones x)
		| x when (x <= 16) -> "p4_ebpf_load_half(skb, src) & " ^ string_of_int (hex_of_ones x)
		| x when (x <= 32) -> "p4_ebpf_load_word(skb, src) & " ^ string_of_int (hex_of_ones x)
		| x -> raise(Failure "bitwidth > 32 unsupported")
		end
	| Unknown -> raise (Failure "not supported yet")

let _p4_header_type_field_extract_ebpf key hdr f =
	let t =  _p4_field_type_ebpf_to_string f.bitwidth  in
	let prim_load = _p4_field_type_prim_load t f.bitwidth in
	let off = match f.offset_from_header with
		| Int x -> x
		| Unknown -> raise (Failure "not supported yet") in

	"static inline " ^ t ^ " p4_ebpf_extract_" ^ hdr.header_type_ref ^ "_" ^ f.field ^ "(struct __sk_buff *skb, unsigned long long offset) =\n" ^
	"{\n" ^
	"\tunsigned long long src = (" ^ (string_of_int off) ^ " + offset);\n" ^
	"\treturn (" ^ prim_load ^ ");\n" ^
	"}\n"
