type p4_counter_type =
	| P4_Counter_Bytes
	| P4_Counter_Packets

type p4_counter_direct_or_static =
	| P4_Counter_Direct of string
	| P4_Counter_Static of string

type p4_counter = {
	counter_ref : string;
	counter_type : p4_counter_type;
	counter_direct_or_static : p4_counter_direct_or_static option;
	counter_min_width : int option;
}

let p4_counters : ((p4_counter list) ref) = ref []

let _p4_add_counter c =
	p4_counters := (c :: !p4_counters)
