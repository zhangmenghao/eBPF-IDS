/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

/* IDS Inspect Uit */
typedef __u8 ids_inspect_unit;
// struct ids_inspect_unit {
	// __u8 unit[IDS_INSPECT_STRIDE];
// };

/* IDS Inspect State */
typedef __u16 ids_inspect_state;

/* Accept state flag */
typedef __u16 accept_state_flag;

/* Key-Value of ids_inspect_map */
struct ids_inspect_map_key {
	ids_inspect_state state;
	ids_inspect_unit unit;
	__u8 padding;
};

struct ids_inspect_map_value {
	ids_inspect_state state;
	accept_state_flag flag;
};

#endif /* __COMMON_KERN_USER_H */
