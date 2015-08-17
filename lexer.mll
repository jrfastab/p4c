(**************************************************************************)
(*                                                                        *)
(*  Menhir                                                                *)
(*                                                                        *)
(*  François Pottier, INRIA Rocquencourt                                  *)
(*  Yann Régis-Gianas, PPS, Université Paris Diderot                      *)
(*                                                                        *)
(*  Copyright 2005-2008 Institut National de Recherche en Informatique    *)
(*  et en Automatique. All rights reserved. This file is distributed      *)
(*  under the terms of the Q Public License version 1.0, with the change  *)
(*  described in file LICENSE.                                            *)
(*                                                                        *)
(**************************************************************************)

{
  open P4_header
  open Parser 

  exception Error of string
}

(* This rule looks for a single line, terminated with '\n' or eof.
   It returns a pair of an optional string (the line that was found)
   and a Boolean flag (false if eof was reached). *)

(*
rule line = shortest
(*
| ([^'\n']* '\n') as line 
    { Some line, true }
*)
(*
| ([^'\n']* ";;") as line
    { Some line, true }
*)

| ((_ * ) ";;") as line
    { Some (line), true }

| eof
    (* Normal case: no data, eof. *)
    { None, false }
(*
| ([^'\n']+ as line) eof
    (* Special case: some data but missing '\n', then eof.
       Consider this as the last line, and add the missing '\n'. *)
    { Some (line ^ ";;"), false }
*)

*)



(* This rule analyzes a single line and turns it into a stream of
   tokens. *)
rule token = parse
| [' ' '\t' ]
    { token lexbuf }
| [ '\n' ]
    {Lexing.new_line lexbuf; token lexbuf }
(*
| '\n'
    { EOL }
*)
| "header_type"
    { HEADER_TYPE }
| "fields"
    { FIELDS }
| "length"
    { LENGTH }
| "max_length"
    { MAX_LENGTH }
| "signed"
    { SIGNED }
| "saturating"
    { SATURATING }
| "header"
    { HEADER }
| "parser"
    { PARSER }
| "extract"
    { EXTRACT }
| "next"
    { NEXT }
| "latest"
    { LATEST }
| "current"
    { CURRENT }
| "select"
    { SELECT }
| "set_metadata"
    { SET_METADATA }
| "return"
    { RETURN }
| "parse_error"
    { PARSE_ERROR }
| "default"
    { DEFAULT }
| "mask"
    { MASK }
| "table"
    { TABLE }
| "reads"
    { READS }
| "min_size"
    { MIN_SIZE }
| "max_size"
    { MAX_SIZE }
| "size"
    { SIZE }
| "support_timeout"
    { SUPPORT_TIMEOUT }
| "exact"
    { EXACT }
| "ternary"
    { TERNARY }
| "lpm"
    { LPM }
| "range"
    { RANGE }
| "valid"
    { VALID }
| "actions"
    { ACTIONS }
| "action_profile"
    { ACTION_PROFILE }
| "control"
    { CONTROL }
| "apply"
    { APPLY }
| "hit"
    { HIT }
| "miss"
    { MISS }
| "action"
    { ACTION }
| "primitive_action"
    { PRIMITIVE_ACTION }
| "void"
    { VOID }
| "header"
    { HDR }
| "field"
    { FIELD }
| "value"
    { VALUE }
| "counter"
    { COUNTER }
| "packet"
    { PACKET }
| "type"
    { TYPE }
| "direct"
    { DIRECT }
| "static"
    { STATIC }
| "bytes"
    { BYTES }
| "packets"
    { PACKETS }
| "if"
    { IF }
| "else"
    { ELSE }
| "or"
    { OR }
| "and"
    { AND }
| "not"
    { NOT }
| "true"
    { TRUE }
| "false"
    { FALSE }
| '~'
    { TILDA }
| '^'
    { CARROT }
| ':'
    { COLON }
| ';'
    { SEMICOLON }
| ','
    { COMMA }
| '*'
    { STAR }
| '!'
    { EXCLAMATION }
| ['0'-'9']+ as i
    { INT (int_of_string i) }
| ['a'-'z' '_']+ as s
    { STRING s }
| '+'
    { PLUS }
| '-'
    { MINUS }
| '*'
    { TIMES }
| '='
    { EQUAL }
| "<<"
    { LSHIFT }
| ">>"
    { RSHIFT }
| "&"
    { LAND }
| "|"
    { LOR }
| '('
    { LPAREN }
| ')'
    { RPAREN }
| '{'
    { LBRACK }
| '}'
    { RBRACK }
| '.'
    { DOT }
| '<'
    { LESSTHAN }
| '>'
    { GREATERTHAN }
| eof
    { EOF }
| _
    {
	let rec get_err_str s p =
		let c = Lexing.lexeme_char lexbuf p in	
		if (c == ' ' || c == '\t' || c == '\n') then
			s
		else
			get_err_str (s ^ Char.escaped c) (p+1)
	in

	let curr = lexbuf.Lexing.lex_curr_p in
	let line = curr.pos_lnum in
	let index = curr.Lexing.pos_cnum - curr.Lexing.pos_bol in
	let err_str = (get_err_str "" 0) in

	let str = Printf.sprintf "%s: %d:%d : unexpected character: %s\n" curr.pos_fname line index err_str in
	raise (Error str)
    }
