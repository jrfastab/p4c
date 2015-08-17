open P4_printer

exception Error of string

module MyPrinter = Make_Printer(P4_pp_bpf.P4_Printer_BPF)
(*module MyPrinter = Make_Printer(P4_pp_match.P4_Printer_Match)*)

let rec repeat channel =
	try
		let result = Parser.main Lexer.token channel in(*(Lexer.token) channel in*)
		match result with
			| Continue -> repeat channel
			| Stop -> Printf.printf "\n"
	with
		| Lexer.Error msg ->
			Printf.fprintf stderr "%s%!" msg;
			raise (Error "")
		| Parser.Error ->
			begin
			let rec get_err_str s p =
				let c = Lexing.lexeme_char channel p in	
				if (c == ' ' || c == '\t' || c == '\n') then
					s
				else
					get_err_str (s ^ Char.escaped c) (p+1)
			in

			let curr = channel.Lexing.lex_curr_p in
			Printf.fprintf stderr "syntax_error %d: %d: %s\n%!"
				curr.pos_lnum
				(curr.Lexing.pos_cnum - curr.Lexing.pos_bol)
				(get_err_str "" 0);
			raise (Error "")
			end
let () =
	if (Array.length Sys.argv - 1) > 1 then
		Printf.printf " Too many arguments\n p4c: [file]"
	else
		begin
		if (Array.length Sys.argv - 1 ) == 1 then
			begin
			let inx = open_in Sys.argv.(1) in
			let lexbuf =  Lexing.from_channel inx in
			lexbuf.lex_curr_p <- { lexbuf.lex_curr_p with pos_fname = Sys.argv.(1)};
			try
				repeat lexbuf;
				Printf.printf "%s" (MyPrinter.pp
							!P4_counters.p4_counters
							!P4_action.p4_action_primitives
							!P4_header_type.p4_header_types
							!P4_header.p4_header
							!P4_table.p4_tables
							!P4_parser.p4_parser
							!P4_control.p4_control
							!P4_action.p4_actions)
			with
				| Error msg ->
					Printf.fprintf stderr "stop code generation\n"
			end
		else
 			repeat (Lexing.from_channel stdin)
		end
