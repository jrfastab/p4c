open P4_header_type

type p4_header_ref = {
	header_ref : string;
	header_instance_name : string;
}

(* p4 header routines *)
let p4_header : ((p4_header_ref list) ref) = ref []

let p4_get_instance_header instance =
	let is_instance a =
		if ((String.compare a.header_instance_name instance) == 0) then true else false
	in

	List.find (is_instance) !p4_header

let p4_get_header header =
	let is_header a =
		if ((String.compare a.header_ref header) == 0) then true else false
	in

	List.find (is_header) !p4_header

let p4_add_header_ref h =
	p4_header := (h :: !p4_header)
