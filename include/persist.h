/* persist.h — crash/reboot-surviving state. */
#ifndef XF_PERSIST_H
#define XF_PERSIST_H

#include "prog.h"

void xf_persist_init(void);

/* Record the program about to be executed so a panic can be attributed to it
 * after reboot. Buffered by default; fsync'd every `fsync_every` calls. */
void xf_persist_mark_pending(const xf_prog *p, uint64_t exec_index);

/* Called at startup: if a pending program exists and a new panic is present,
 * save it as a reproducer and clear the marker. Returns true if a crash was
 * attributed. */
bool xf_persist_post_reboot_check(void);

/* Read/write the global execution counter across reboots. */
uint64_t xf_persist_load_counter(void);
void     xf_persist_store_counter(uint64_t v);

#endif /* XF_PERSIST_H */
