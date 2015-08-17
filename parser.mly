%{
open P4_header_type
open P4_header
open P4_parser
open P4_control
open P4_table
open P4_action
open P4_counters
open P4_core
%}

(* header type tokens *)
%token HEADER_TYPE
%token FIELDS LENGTH MAX_LENGTH
%token SIGNED SATURATING

(* header tokens *)
%token HEADER

(* parser tokens *)
%token PARSER
%token EXTRACT SELECT SET_METADATA
%token NEXT LATEST CURRENT
%token RETURN PARSE_ERROR DEFAULT MASK PACKET

(* table tokens *)
%token TABLE
%token READS ACTIONS MIN_SIZE MAX_SIZE SIZE SUPPORT_TIMEOUT
%token EXACT TERNARY LPM RANGE
%token ACTION_PROFILE

(* control flow *)
%token CONTROL
%token APPLY HIT MISS
%token IF ELSE OR AND
%token LAND LOR TILDA CARROT NOT STAR LESSTHAN GREATERTHAN EXCLAMATION EQUAL

(* action tokens *)
%token PRIMITIVE_ACTION ACTION
%token VOID HDR FIELD VALUE

(* counters *)
%token COUNTER TYPE MIN_WIDTH DIRECT STATIC BYTES PACKETS

(* common tokens *)
%token VALID
%token LBRACK RBRACK COMMA SEMICOLON COLON

%token <string> STRING
%token <int> INT
%token LSHIFT RSHIFT PLUS MINUS TIMES LPAREN RPAREN DOT
%token TRUE FALSE

%token EOF

%left LSHIFT RSHIFT
%left PLUS MINUS        /* lowest precedence */
%left TIMES             /* medium precedence */

(*
%start <string> main
*)
%start <P4_core.input> main

%%

(*
main:
| stmts = list(_main);
    { "" }
    {List.fold_left ( fun str s -> str ^ s ) "" stmts}
*)

main:
| s = list(stmts); EOF
	{ Stop }

stmts:
| PARSER p4_parser = parser_type
    { Continue }
| HEADER_TYPE  header = header_type
    { Continue }
| HEADER header = header
    { Continue }
| TABLE table = table
    { Continue }
| CONTROL control = control
    { Continue }
| PRIMITIVE_ACTION action_primitive = action_primitive
    { Continue }
| ACTION action = action
    { Continue }
| COUNTER counter = counter
    { Continue }
(*
| EOF
    { Stop }
*)

(* Header Type Block *)
header_type:
| ref = STRING; LBRACK; h = header_dec_body; RBRACK;
    {
	let r = {header_type_ref = ref; header_type = h;} in
	p4_add_header_type_ref r;
    }

header_dec_body: 
| FIELDS; LBRACK; fields = separated_list(SEMICOLON, field_dec) RBRACK;
  LENGTH; length = length_expr; SEMICOLON;
  MAX_LENGTH; max = INT; SEMICOLON;
    { {fields = fields; length = None; max = None} }
| FIELDS; LBRACK; fields = separated_list(SEMICOLON, field_dec) RBRACK;
  LENGTH; length = length_expr; SEMICOLON;
    { {fields = fields; length = None; max = None} }
| FIELDS; fields = delimited(LBRACK, list(field_dec), RBRACK);
    { {fields = fields; length = None; max = None} }

field_dec:
| field = STRING; COLON; width = fields_bitwidth;
  LPAREN; fmod = separated_list(COMMA, field_mod); RPAREN; SEMICOLON;
    { {field = field; bitwidth = width; offset_from_header = Unknown; mods = Some fmod} }
| field = STRING; COLON; width = fields_bitwidth; SEMICOLON;
    { {field = field; bitwidth = width; offset_from_header = Unknown; mods = None} }

field_mod:
| SIGNED;
    { Signed }
| SATURATING;
    { Saturating }

fields_bitwidth:
| i = INT 
    { Int i }
| STAR 
    { Unknown }

length_expr:
| v1 = length_expr; PLUS; v2 = length_expr;
    {}
| v1 = length_expr; MINUS; v2 = length_expr;
    {}
| v1 = length_expr; TIMES; v2 = length_expr;
    {}
| v1 = length_expr; LSHIFT; v2 = length_expr;
    {}
| v1 = length_expr; RSHIFT; v2 = length_expr;
    {}
| v = INT;
    { }
| v = STRING;
    { }

(* Header Block *)
header:
| ref = STRING; instance_name = STRING; SEMICOLON;
    {
	let r = {header_ref = ref; header_instance_name = instance_name} in
	p4_add_header_ref r;
    }

(* Parser Block *)
parser_type:
| ref = STRING; LBRACK; p = parser_fun_body; RBRACK; SEMICOLON;
    {
	p4_add_parser_type_ref {parser_ref = ref; p4_parser = p;}
    }

parser_fun_body:
| x = parser_e_or_s; SEMICOLON; s = parser_return; SEMICOLON;
    { {extract_or_set = Some x; return = s;} }
| s = parser_return; SEMICOLON;
    { {extract_or_set = None; return = s;} }

parser_e_or_s:
| EXTRACT; LPAREN; h = parser_extract_ref; RPAREN;
	{ Extract h }
| SET_METADATA; LPAREN; s = parser_set_statement; RPAREN;
	{ Set s }

parser_case_return_value_type:
| RETURN; v = STRING;
	{ State_function v }
| RETURN; PARSE_ERROR; v = STRING;
	{ Parse_error v } 

parser_value_or_masked:
| v = INT
	{ Value_or_masked_value (0, v)}
| v1 = INT; MASK;  v2 = INT;
	{ Value_or_masked_mask (0, v1, v2)}
| v = STRING
	{ Value_or_masked_name v}

parser_value_list:
| v = separated_list(COMMA, parser_value_or_masked)
	{ Value_or_masked v }
| DEFAULT
	{ Default }

parser_case_entry:
| v = parser_value_list; COLON; c = parser_case_return_value_type; SEMICOLON
	{ {value_list = v; case_return_value = c} }

parser_return:
| RETURN; SELECT; LPAREN; s = separated_list(COMMA, field_or_data_ref); RPAREN; LBRACK; c = list(parser_case_entry); RBRACK;
	{ Select {select = s; case = c} }
| v = parser_case_return_value_type
	{ (Value v) }

parser_set_statement:
| f = STRING; COMMA; m = metadata_expr;
	{ {field_ref = f; metadata_expr = m} } 

parser_extract_ref:
| i1 = STRING; LBRACK; index = parser_header_extract_index; RBRACK;
	{ {instance = i1; index = Some index} }
| i1 = STRING;
	{ {instance = i1; index = None} }

parser_header_extract_index:
| NEXT
	{ Next }
| v = INT
	{ Index v }

metadata_expr:
| value = INT;
	{ Field_value value }
| value = field_or_data_ref;
	{ Field_md_ref value }

field_or_data_ref:
| CURRENT; LPAREN; c1 = INT; COMMA; c2 = INT; RPAREN;
	{ Current (c1, c2) }
| LATEST; DOT; field = STRING;
	{ Latest field }
| field = STRING;
	{ Field_ref field }

(* Table Block *)
table:
| table_name = STRING; table = table_body; SEMICOLON;
	{
		let t =  {table_ref = table_name; p4_table = table;} in
		p4_add_table t;  
	}

table_body:
| LBRACK; reads = option(table_reads); a = table_actions; min = option(table_min_size); max = option(table_max_size); size = option(table_size); support_timeout = option(table_support_timeout); RBRACK
	{ {reads = reads; table_actions = a;
	   min_size = min; max_size = max; size = size;
	   support_timeout= support_timeout;} }

table_reads:
| READS; LBRACK; field_match = list(field_match); RBRACK;
	{ field_match }

field_match:
| field_or_masked_ref = field_or_masked_ref; COLON; field_match_type = field_match_type; SEMICOLON;
	{ {field_or_masked_ref = field_or_masked_ref; field_match_type = field_match_type;} }

field_or_masked_ref:
| header = STRING; DOT; field = STRING; MASK; const_value = INT;
	{ Field_ref_mask (header, field, const_value) }
| header = STRING; DOT; field = STRING;
	{ Field_ref_field (header, field) }
| header = STRING;
	{ Field_ref_header header }

field_match_type:
| EXACT
	{ Field_match_type_exact }
| TERNARY 
	{ Field_match_type_ternary }
| LPM
	{ Field_match_type_lpm }
| RANGE 
	{ Field_match_type_range }
| VALID
	{ Field_match_type_valid }

table_actions:
| ACTIONS; LBRACK; action_names = list(action_name); RBRACK;
	{ Table_action_spec action_names }
| ACTION_PROFILE; COLON; profile = STRING; SEMICOLON;
	{ Table_action_profile profile }

action_name:
| name = STRING; SEMICOLON;
	{ name }

table_min_size:
| MIN_SIZE; COLON; size = INT; SEMICOLON;
	{ size }

table_max_size:
| MAX_SIZE; COLON; size = INT; SEMICOLON;
	{ size }

table_size:
| SIZE; COLON; size = INT; SEMICOLON;
	{ size }

table_support_timeout:
| SUPPORT_TIMEOUT; COLON; TRUE; SEMICOLON;
	{ true }
| SUPPORT_TIMEOUT; COLON; FALSE; SEMICOLON;
	{ false }

(* Control Flow Block *)
control:
| control_fn_name = STRING; LBRACK control_statements = list(control_statement); RBRACK;
	{
	  _p4_add_control {control_ref = control_fn_name; control_block = control_statements}
	}

control_block:
| LBRACK; control_statement = control_statement; RBRACK
	{ Action_control_block control_statement }

control_statement:
| v = control_apply_table_call;
	{ Apply_table_call v }
| v = control_apply_and_select_block;
	{ Apply_and_select_block v }
| v = control_if_else_statement;
	{ If_else_statement v }
| v = STRING; LPAREN; RPAREN; SEMICOLON;
	{ Control_fn_name v }

control_apply_table_call:
| APPLY; LPAREN; t = STRING; RPAREN; SEMICOLON
	{ t }

control_apply_and_select_block:
| APPLY; LPAREN; t = STRING; RPAREN; LBRACK; c = control_apply_case; RBRACK
	{ {control_table = t; control_case_list = c} }

control_action:
| DEFAULT c = control_block;
	{ {control_action = Action_default; control_action_block = c} }
| HIT;  c = control_block;
	{ {control_action = Action_hit; control_action_block = c} }
| MISS;  c = control_block;
	{ {control_action = Action_miss; control_action_block = c} }
| a = STRING; c = control_block;
	{ {control_action = Action_name a; control_action_block = c} }

control_apply_case:
| action_case = list(control_action)
	{Action_case action_case}

control_if_else_statement:
| IF; LPAREN; bool_expr = control_bool_expr; RPAREN; control_block = control_block;
  else_block = option(control_else);
	{ {bool_expr = bool_expr; if_control_block = control_block; else_block = else_block} }

control_else:
| ELSE; else_block = control_block;
	{ Control_else_block else_block }
| ELSE; if_else_statement = control_if_else_statement;
	{ Control_else_if_else_block if_else_statement}

control_bool_expr:
| VALID; LPAREN; header_ref = STRING; RPAREN;
	{ Control_bool_header_ref header_ref }
| bool_expr0 = control_bool_expr; bool_op = control_bool_op; bool_expr1 = control_bool_expr;
	{ Control_bool_op_expr (bool_expr0, bool_op, bool_expr1) }
| NOT; bool_expr = control_bool_expr;
	{ Control_bool_op_not bool_expr }
| LPAREN; bool_expr = control_bool_expr; RPAREN;
	{ Control_bool_op_paren bool_expr }
| exp0 = control_bool_expr_exp; rel_op = control_rel_op; exp1 = control_bool_expr_exp
	{ Control_bool_op_relop (exp0, rel_op, exp1) }
| TRUE
	{ Control_bool_op_true }
| FALSE 
	{ Control_bool_op_false }

control_rel_op:
| GREATERTHAN;
	{ GreaterThan } 
| GREATERTHAN; EQUAL;
	{ GreaterThanOrEqual } 
| EQUAL; EQUAL;
	{ Equal } 
| LESSTHAN;
	{ LessThan } 
| LESSTHAN; EQUAL;
	{ LessThanOrEqual } 
| EXCLAMATION; EQUAL;
	{ NotEqual } 

control_bool_expr_exp:
| exp0 = control_bool_expr_exp; bin_op = control_bool_expr_exp_bin_op;  exp1 = control_bool_expr_exp;
	{ Control_bool_op_exp_exp (exp0, bin_op, exp1)}
| un_op = control_bool_expr_exp_un_op; exp0 = control_bool_expr_exp;
	{ Control_bool_op_exp_un_op (un_op, exp0)}
| h = STRING; DOT; f = STRING;
	{ Control_bool_op_exp_field {control_header = h; control_field = f;} }
| value = INT;
	{ Control_bool_op_exp_value value}
| LPAREN;  exp0 = control_bool_expr_exp; RPAREN;
	{ Control_bool_op_exp_paren exp0}

control_bool_expr_exp_un_op:
| TILDA
	{ Control_bool_op_exp_un_op_tilda }
| MINUS
	{ Control_bool_op_exp_un_op_negate }

control_bool_expr_exp_bin_op:
| PLUS
	{ Control_bool_expr_exp_bin_op_plus }
| STAR 
	{ Control_bool_expr_exp_bin_op_star }
| MINUS 
	{ Control_bool_expr_exp_bin_op_minus }
| LSHIFT 
	{ Control_bool_expr_exp_bin_op_lshift }
| RSHIFT 
	{ Control_bool_expr_exp_bin_op_rshift }
| LAND 
	{ Control_bool_expr_exp_bin_op_land }
| LOR 
	{ Control_bool_expr_exp_bin_op_lor }
| CARROT 
	{ Control_bool_expr_exp_bin_op_carrot }

control_bool_op:
| OR
	{ Control_bool_op_or }
| AND 
	{ Control_bool_op_and }

(* Action Primitive Block *)
action_primitive:
| ref = STRING; LPAREN; params = separated_list(COMMA, action_param_list); RPAREN; SEMICOLON
	{
		let prim = {p4_action_primitive_ref = ref; p4_action_primitive = params} in
		_p4_add_action_primitive_type_ref prim	
	}

action_param_list:
| VOID
	{ P4_Action_Arg_Void_T }
| HDR; header = STRING
	{ P4_Action_Arg_Header_T header}
| FIELD; field = STRING
	{ P4_Action_Arg_Field_T field}
| VALUE; value = STRING
	{ P4_Action_Arg_Value_T value}
| MASK; mask = STRING
	{ P4_Action_Arg_Mask_T mask}
| COUNTER; counter = STRING
	{ P4_Action_Arg_Counter_T counter}
| PACKET; pkt = STRING
	{ P4_Action_Arg_Packet_T pkt}

(* Action Block *)
action:
| ref = STRING; LPAREN; params = separated_list(COMMA, action_param_list); RPAREN; LBRACK
	stmts = option(list(action_statement_list));
	RBRACK;
	{
		let action = {p4_action_ref = ref; p4_actions_args = params; p4_actions_stmts = stmts} in
		_p4_add_action_ref action
	}

action_statement_list:
| func = STRING; LPAREN; args = option(separated_list(COMMA, STRING)); RPAREN; SEMICOLON
	{ {p4_action_stmt = func; p4_action_stmt_args = args} }

(* Counter Block *)
counter:
| ref = STRING; LBRACK; counter_type = counter_type;
	direct_or_static = option(counter_direct_or_static);
	min_width = option(counter_min_width); RBRACK
	{
		let c = {counter_ref = ref; counter_type = counter_type;
			 counter_direct_or_static = direct_or_static;
			 counter_min_width = min_width;}
		in

		_p4_add_counter c
	}

counter_type:
| TYPE; COLON;  BYTES; SEMICOLON;
	{ P4_Counter_Bytes }
| TYPE; COLON; PACKETS; SEMICOLON;
	{ P4_Counter_Packets }

counter_direct_or_static:
| DIRECT; COLON; table_ref = STRING; SEMICOLON;
	{ P4_Counter_Direct table_ref }
| STATIC; COLON; table_ref = STRING; SEMICOLON;
	{ P4_Counter_Static table_ref }

counter_min_width:
| min_width = INT
	{ min_width } 
