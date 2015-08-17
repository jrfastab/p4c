let rec hex_of_ones' x set =
	if set > 0 then
		hex_of_ones' (x lor (1 lsl set)) (set - 1)
	else
		(x lor (1 lsl set))

let hex_of_ones set =
	hex_of_ones' 0 (set - 1)

let _p4_ebpf_load_pkt_byte_def =
"
unsigned long long p4_ebpf_load_byte(void *skb, unsigned long long offset)
	asm (\"llvm.bpf.load.byte\");
"

let _p4_ebpf_load_pkt_half_def =
"
unsigned long long p4_ebpf_load_half(void *skb, unsigned long long offset)
	asm (\"llvm.bpf.load.half\");
"

let _p4_ebpf_load_pkt_word_def =
"
unsigned long long p4_ebpf_load_word(void *skb, unsigned long long offset)
	asm (\"llvm.bpf.load.word\");
"

let _p4_ebpf_primitive_mvu_template lside rside mask maske shift term =
	let stmt =
		if (mask == maske) then
			lside ^ rside ^ ")"
		else
			if shift != 0 then
				let rshift = Printf.sprintf ") >> %i) & 0x%x" shift mask in
				lside ^ "(" ^ rside ^ rshift
			else
				let rshift = Printf.sprintf ") & 0x%x" mask in
				lside ^ rside ^ rshift
	in

	if term == true then (stmt ^ ";\n") else stmt


let _p4_ebpf_primitive_mvu8 skb offv off shift mask =
	let lside = "\treturn " in
	let rside = "p4_ebpf_load_byte(" ^ skb ^ ", " ^ offv ^ " + " ^ string_of_int off in

	_p4_ebpf_primitive_mvu_template lside rside mask 8 shift true
		
let _p4_ebpf_primitive_mvu16 skb offv off shift mask =
	let lside = "\treturn " in
	let rside = "p4_ebpf_load_half(" ^ skb ^ ", " ^ offv ^ " + " ^ string_of_int off in

	_p4_ebpf_primitive_mvu_template lside rside mask 16 shift true

let _p4_ebpf_primitive_mvu32 skb offv off shift mask =
	let lside = "\treturn " in
	let rside = "p4_ebpf_load_word(" ^ skb ^ ", " ^ offv ^ " + " ^ string_of_int off in

	_p4_ebpf_primitive_mvu_template lside rside mask 32 shift true

let _p4_ebpf_primitive_mvu64 skb offv off shift mask =
	let lside = "\treturn" in
	let rside x = "p4_ebpf_load_word(" ^ skb ^ ", " ^ offv ^ " + " ^ string_of_int (off + x) in

	let load32 = lside ^ " " ^ rside 0 ^ ") | ((" in

	(_p4_ebpf_primitive_mvu_template load32 (rside 4) (mask lsr 32) 32 shift false) ^ ")" ^ " << 32);\n"

let _p4_ebpf_common_headers =
"#include <asm/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/in.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_tunnel.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>

struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 id;
};

#define ELF_SECTION_LICENSE	\"license\"
#define ELF_SECTION_MAPS	\"maps\"
#define ELF_SECTION_CLASSIFIER	\"classifier\"
#define ELF_SECTION_ACTION	\"action\"

#define ELF_MAX_MAPS		64
#define ELF_MAX_LICENSE_LEN	128

#ifndef __section
# define __section(NAME)	__attribute__((section(NAME), used))
#endif

static void *(*p4_map_lookup_elem)(void *map, void *key) =
	(void *) BPF_FUNC_map_lookup_elem;

static void *(*p4_map_update_elem)(void *map, void *key, void *value, unsigned long long flags) =
	(void *) BPF_FUNC_map_lookup_elem;
"

let _p4_preamble_ebpf =
	_p4_ebpf_common_headers ^
	_p4_ebpf_load_pkt_byte_def ^
	_p4_ebpf_load_pkt_half_def ^
	_p4_ebpf_load_pkt_word_def ^ "\n"
