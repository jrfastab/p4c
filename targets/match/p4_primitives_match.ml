let preamble =
"
#include \"if_match.h\"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array)/sizeof(array[0]))
#endif /* ARRAY_SIZE */

static char empty[] = \"\";

"

let p4_preamble_match =
	preamble
