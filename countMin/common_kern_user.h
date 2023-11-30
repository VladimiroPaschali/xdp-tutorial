/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

/* This is the data record stored in the map */
struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;

};

#define CMS_ROWS 4
#define CMS_SIZE 131072
// #define CMS_SIZE 10


#define RIGA 0
// #define COLONNA 131071
#define COLONNA 84130


struct Cms {
    int cms[CMS_ROWS][CMS_SIZE];
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */
