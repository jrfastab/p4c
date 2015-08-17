open Batteries
open P4_header_type

(* Set of data type to p4 printers *)
let _p4_field_mod_p4 xs =
 match xs with
 | Some x ->
	" (" ^
	begin
 	List.fold_left (fun str x -> 
	let space = if String.is_empty str then "" else ", " in
	match x with
		| Signed -> str ^ space ^ "signed"
		| Saturating -> str ^ space ^ "saturating"
	) "" x
	end ^ ")"
 | None -> ""

let _p4_bitwidth_p4 = function
	| Int x -> (string_of_int x)
	| Unknown -> "*"

let _p4_field_p4 f =
	f.field ^ " : " ^ _p4_bitwidth_p4 f.bitwidth ^ _p4_field_mod_p4 f.mods ^ "; "

let _p4_field_length_op_p4 = function
	| P4_FIELD_PLUS -> "+"
	| P4_FIELD_MINUS -> "-"
	| P4_FIELD_TIMES -> "*"
	| P4_FIELD_SLEFT -> "<<"
	| P4_FIELD_SRIGHT -> ">>"

let rec _p4_field_length_p4 = function
	| INT i -> string_of_int i
	| FIELD s -> s
	| BINOP (fl1, fop, fl2) ->
		_p4_field_length_p4 fl1 ^
		_p4_field_length_op_p4 fop ^
		_p4_field_length_p4 fl2

let _p4_fields_p4 xs =
	List.fold_left (fun str x -> str ^ _p4_field_p4 x) "" xs

let _p4_length_p4 = function
	| Some x -> _p4_field_length_p4 x
	| None -> ""

let _p4_max_p4 = function
	| Some x -> string_of_int x
	| None -> ""

let _p4_header_type_p4 x =
	"\tfields { " ^ _p4_fields_p4 x.fields ^ " }\n" ^
	"\tlength : " ^ _p4_length_p4 x.length ^ ";\n" ^
	"\tmax_length : " ^ _p4_max_p4 x.max ^ ";\n"

let _p4_header_type_ref_p4 (x : p4_header_type_ref) =
	"header_type " ^ x.header_type_ref ^ " {\n" ^
		_p4_header_type_p4 x.header_type ^ "}\n"

(* Set of data type to C API printers *)
(*
let _p4_field_mod_match xs =
 match xs with
 | Some x ->
	" (" ^
	begin
 	List.fold_left (fun str x -> 
	let space = if String.is_empty str then "" else ", " in
	match x with
		| Signed -> str ^ space ^ "signed"
		| Saturating -> str ^ space ^ "saturating"
	) "" x
	end ^ ")"
 | None -> ""
*)

let _p4_bitwidth_match = function
	| Int x -> (string_of_int x)
	| Unknown -> "0"

let _p4_field_match p f =
	"\t{ .name = " ^ f.field ^ ",\n" ^
	"\t  .uid = HEADER_" ^ String.uppercase p ^ "_" ^ String.uppercase f.field ^ ",\n" ^
	"\t  .bitwidth = " ^ _p4_bitwidth_match f.bitwidth ^ ",},\n"

let _p4_field_match_define p f =
	"\tHEADER_" ^ String.uppercase p ^ "_" ^ String.uppercase f.field ^ ",\n"

(*
let _p4_field_length_op_match = function
	| P4_FIELD_PLUS -> "+"
	| P4_FIELD_MINUS -> "-"
	| P4_FIELD_TIMES -> "*"
	| P4_FIELD_SLEFT -> "<<"
	| P4_FIELD_SRIGHT -> ">>"

let rec _p4_field_length_match = function
	| INT i -> string_of_int i
	| FIELD s -> s
	| BINOP (fl1, fop, fl2) ->
		_p4_field_length_match fl1 ^
		_p4_field_length_op_match fop ^
		_p4_field_length_match fl2
*)

let _p4_fields_match p xs =
	List.fold_left (fun str x -> str ^ _p4_field_match p x) "" xs

let _p4_fields_match_defines p xs =
	List.fold_left (fun str x -> str ^ _p4_field_match_define p x) "" xs

(*
let _p4_length_match = function
	| Some x -> _p4_field_length_match x
	| None -> ""

let _p4_max_match = function
	| Some x -> string_of_int x
	| None -> ""
*)

let _p4_header_type_ref_match prefix x =
	_p4_fields_match prefix x.fields

let _p4_header_type_match_defines prefix x =
	_p4_fields_match_defines prefix x.fields

let _p4_header_type_match (x : p4_header_type_ref) =
	"static char " ^ x.header_type_ref ^ "_str[] = \"" ^ x.header_type_ref ^ "\";\n\n" ^

	"enum ies_header_" ^ x.header_type_ref ^ "_ids {\n" ^
	"\tHEADER_" ^ String.uppercase x.header_type_ref ^ "_UNSPEC = 0,\n" ^
	_p4_header_type_match_defines x.header_type_ref x.header_type ^
	"};\n\n" ^

	"static struct net_mat_field " ^ x.header_type_ref ^ "_fields[] = {\n" ^
	_p4_header_type_ref_match x.header_type_ref x.header_type ^ 
	"};\n\n" ^

	"static struct net_mat_hdr " ^ x.header_type_ref ^ " {\n" ^
	"\t.name = " ^ x.header_type_ref ^ "_str,\n" ^
	"\t.uid = HEADER_" ^ String.uppercase x.header_type_ref ^ ",\n" ^
	"\t.field_sz = ARRAY_SIZE(" ^ x.header_type_ref ^ "_fields),\n" ^
	"\t.fields = " ^ x.header_type_ref ^ "_fields,\n" ^
	"};\n"

let _p4_header_type_ref_match x =
	List.fold_left (fun s t -> s ^ _p4_header_type_match t) "" x
