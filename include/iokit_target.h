/* iokit_target.h — discovered IOKit user-client targets (Apple drivers). */
#ifndef XF_IOKIT_TARGET_H
#define XF_IOKIT_TARGET_H

#include "xfuzz.h"

#define XF_IOKIT_MAX_TARGETS 512

typedef struct {
    uint64_t entry_id;          /* IORegistryEntryID — stable within a boot */
    uint32_t open_type;         /* userclient type selector that opened it   */
    uint32_t max_selector;      /* selectors to fuzz: 0..max_selector-1      */
    char     client_class[128]; /* IOUserClientClass (Apple driver name)     */
    char     provider[128];     /* provider service class                    */
    uint32_t hits;              /* connections successfully opened           */
    bool     dangerous;         /* on the safe-mode denylist                 */
} xf_iokit_target;

/* Populated by xf_iokit_discover(). */
extern xf_iokit_target g_iokit_targets[XF_IOKIT_MAX_TARGETS];
extern uint32_t        g_iokit_ntargets;

/* IOKit-specific arg layout indices within an IOKit xf_call_desc. */
enum {
    XF_IOK_ARG_SELECTOR   = 0,  /* method selector                          */
    XF_IOK_ARG_SCALARS    = 1,  /* scalar input array (blob of uint64s)     */
    XF_IOK_ARG_STRUCT_IN  = 2,  /* struct input buffer                      */
    XF_IOK_ARG_STRUCT_OUT = 3,  /* requested struct output size             */
    XF_IOK_ARG_COUNT      = 4,
};

#endif /* XF_IOKIT_TARGET_H */
