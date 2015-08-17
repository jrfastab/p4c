open Batteries

type p4_field_mod =
	| Signed
	| Saturating

type p4_bitwidth =
	| Int of int
	| Unknown


type p4_field = {
	field : string;
	bitwidth : p4_bitwidth;
	offset_from_header : p4_bitwidth;
	mods : p4_field_mod list option;
}

type p4_field_length_op =
	| P4_FIELD_PLUS
	| P4_FIELD_MINUS
	| P4_FIELD_TIMES
	| P4_FIELD_SLEFT
	| P4_FIELD_SRIGHT
	
type p4_field_length = 
	| INT of int
	| FIELD of string
	| BINOP of p4_field_length * p4_field_length_op * p4_field_length

type p4_header_type = {
	fields : p4_field list;
	length : p4_field_length option;
	max    : int option
}

type p4_header_type_ref = {
	header_type_ref    : string;
	header_type : p4_header_type;
}

(* P4 Header Routines *)
let p4_header_types : ((p4_header_type_ref list) ref) = ref []

let p4_get_header_type name =
	let is_header a =
		if ((String.compare a.header_type_ref name) == 0) then true else false
	in
	List.find (is_header) !p4_header_types

let p4_get_field header field =
	let is_field f =
		if (String.compare f.field field) == 0 then true else false
	in
	let h = p4_get_header_type header in
	let fields = h.header_type.fields in

	List.find (is_field) fields

let rec p4_header_type_abs_fields fields fs offset =
	match fields with
	| x :: xs ->
		let f = { field = x.field;
			  bitwidth = x.bitwidth;
			  offset_from_header = Int offset;
			  mods = x.mods} in
		let off = offset + (match x.bitwidth with
		| Int x -> x
		| Unknown -> raise(Failure "do not support unknown lengths yet")) in

		p4_header_type_abs_fields xs (f :: fs) off
	| [] -> fs

let p4_header_type_ref_abs_offsets h =
	{ header_type_ref = h.header_type_ref;
	  header_type = {
		fields = p4_header_type_abs_fields h.header_type.fields [] 0;
		length = h.header_type.length;
		max = h.header_type.max;
	  }
	}

let p4_add_header_type_ref h =
	p4_header_types := ((p4_header_type_ref_abs_offsets h) :: !p4_header_types)
