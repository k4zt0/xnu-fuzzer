/*
 * bsd_desc.c — BSD/Unix syscall interface descriptions for XNU arm64.
 *
 * Two layers:
 *   (1) A curated, typed table of high-value syscalls that produce/consume
 *       resources (fds), so the generator builds meaningful sequences.
 *   (2) A generated "raw" layer covering every syscall number 0..557 with
 *       generic integer/pointer args, so no entry point is left untouched.
 */
#include "desc.h"

#include <sys/syscall.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

/* ----- Flag sets --------------------------------------------------------- */
static const uint64_t open_flags[]  = {
    0x0000 /*RDONLY*/, 0x0001 /*WRONLY*/, 0x0002 /*RDWR*/, 0x0004 /*NONBLOCK*/,
    0x0008 /*APPEND*/, 0x0200 /*CREAT*/, 0x0400 /*TRUNC*/, 0x0800 /*EXCL*/,
    0x1000000 /*CLOEXEC*/, 0x20 /*SHLOCK*/, 0x40 /*EXLOCK*/, 0x100000 /*SYMLINK*/,
};
static const uint64_t prot_flags[]  = { 0x1 /*R*/, 0x2 /*W*/, 0x4 /*X*/ };
static const uint64_t map_flags[]   = {
    0x0001 /*SHARED*/, 0x0002 /*PRIVATE*/, 0x0010 /*FIXED*/, 0x1000 /*ANON*/,
    0x0400 /*NORESERVE*/, 0x0800 /*NOEXTEND*/,
};
static const uint64_t sock_domain[] = { 1 /*UNIX*/, 2 /*INET*/, 30 /*INET6*/, 32 /*SYSTEM*/ };
static const uint64_t sock_type[]   = { 1 /*STREAM*/, 2 /*DGRAM*/, 3 /*RAW*/ };

#define FLAGS(arr) .flags = (arr), .flag_count = (uint32_t)XF_ARRAY_LEN(arr)

/* Shorthand arg constructors. */
#define A_FD(nm)        { .name=nm, .type=XF_ARG_RESOURCE, .res_kind=XF_RES_FD }
#define A_INT(nm)       { .name=nm, .type=XF_ARG_INT }
#define A_CONST(nm,v)   { .name=nm, .type=XF_ARG_CONST, .const_val=(v) }
#define A_STR(nm)       { .name=nm, .type=XF_ARG_STRING, .buf_min=1, .buf_max=64 }
#define A_PTR_IN(nm)    { .name=nm, .type=XF_ARG_PTR, .dir=XF_DIR_IN,  .buf_min=0, .buf_max=512 }
#define A_PTR_OUT(nm)   { .name=nm, .type=XF_ARG_PTR, .dir=XF_DIR_OUT, .buf_min=0, .buf_max=512 }
#define A_PTR_IO(nm)    { .name=nm, .type=XF_ARG_PTR, .dir=XF_DIR_INOUT,.buf_min=0,.buf_max=512 }
#define A_LEN(nm,ref)   { .name=nm, .type=XF_ARG_LEN, .len_ref=(ref) }
#define A_FLAGS(nm,arr) { .name=nm, .type=XF_ARG_FLAGS, FLAGS(arr) }

/* ----- Curated typed table ----------------------------------------------- */
static const xf_call_desc k_bsd[] = {
  { .name="open", .surface=XF_SURFACE_BSD, .number=SYS_open, .nargs=3,
    .args={ A_STR("path"), A_FLAGS("flags", open_flags), A_CONST("mode",0644) },
    .produces=XF_RES_FD },

  { .name="openat", .surface=XF_SURFACE_BSD, .number=SYS_openat, .nargs=4,
    .args={ A_CONST("dirfd",-2/*AT_FDCWD*/), A_STR("path"),
            A_FLAGS("flags", open_flags), A_CONST("mode",0644) },
    .produces=XF_RES_FD },

  { .name="shm_open", .surface=XF_SURFACE_BSD, .number=SYS_shm_open, .nargs=3,
    .args={ A_STR("name"), A_FLAGS("flags", open_flags), A_CONST("mode",0644) },
    .produces=XF_RES_FD },

  { .name="socket", .surface=XF_SURFACE_BSD, .number=SYS_socket, .nargs=3,
    .args={ A_FLAGS("domain", sock_domain), A_FLAGS("type", sock_type), A_INT("proto") },
    .produces=XF_RES_FD },

  { .name="kqueue", .surface=XF_SURFACE_BSD, .number=SYS_kqueue, .nargs=0,
    .produces=XF_RES_FD },

  { .name="dup", .surface=XF_SURFACE_BSD, .number=SYS_dup, .nargs=1,
    .args={ A_FD("fd") }, .produces=XF_RES_FD },

  { .name="read", .surface=XF_SURFACE_BSD, .number=SYS_read, .nargs=3,
    .args={ A_FD("fd"), A_PTR_OUT("buf"), A_LEN("nbyte",1) } },

  { .name="write", .surface=XF_SURFACE_BSD, .number=SYS_write, .nargs=3,
    .args={ A_FD("fd"), A_PTR_IN("buf"), A_LEN("nbyte",1) } },

  { .name="ioctl", .surface=XF_SURFACE_BSD, .number=SYS_ioctl, .nargs=3,
    .args={ A_FD("fd"), A_INT("request"), A_PTR_IO("argp") } },

  { .name="fcntl", .surface=XF_SURFACE_BSD, .number=SYS_fcntl, .nargs=3,
    .args={ A_FD("fd"), A_INT("cmd"), A_INT("arg") } },

  { .name="setsockopt", .surface=XF_SURFACE_BSD, .number=SYS_setsockopt, .nargs=5,
    .args={ A_FD("fd"), A_INT("level"), A_INT("optname"),
            A_PTR_IN("optval"), A_LEN("optlen",3) } },

  { .name="getsockopt", .surface=XF_SURFACE_BSD, .number=SYS_getsockopt, .nargs=5,
    .args={ A_FD("fd"), A_INT("level"), A_INT("optname"),
            A_PTR_OUT("optval"), A_PTR_IO("optlen") } },

  { .name="mmap", .surface=XF_SURFACE_BSD, .number=SYS_mmap, .nargs=6,
    .args={ A_CONST("addr",0), A_INT("len"), A_FLAGS("prot", prot_flags),
            A_FLAGS("flags", map_flags), A_FD("fd"), A_INT("offset") } },

  { .name="munmap", .surface=XF_SURFACE_BSD, .number=SYS_munmap, .nargs=2,
    .args={ A_INT("addr"), A_INT("len") } },

  { .name="mprotect", .surface=XF_SURFACE_BSD, .number=SYS_mprotect, .nargs=3,
    .args={ A_INT("addr"), A_INT("len"), A_FLAGS("prot", prot_flags) } },

  { .name="madvise", .surface=XF_SURFACE_BSD, .number=SYS_madvise, .nargs=3,
    .args={ A_INT("addr"), A_INT("len"), A_INT("advice") } },

  { .name="sysctl", .surface=XF_SURFACE_BSD, .number=SYS_sysctl, .nargs=6,
    .args={ A_PTR_IN("name"), A_INT("namelen"), A_PTR_OUT("old"),
            A_PTR_IO("oldlenp"), A_PTR_IN("new"), A_LEN("newlen",4) } },

  { .name="sysctlbyname", .surface=XF_SURFACE_BSD, .number=SYS_sysctlbyname, .nargs=6,
    .args={ A_STR("name"), A_LEN("namelen",0), A_PTR_OUT("old"),
            A_PTR_IO("oldlenp"), A_PTR_IN("new"), A_LEN("newlen",4) } },

  { .name="getattrlist", .surface=XF_SURFACE_BSD, .number=SYS_getattrlist, .nargs=5,
    .args={ A_STR("path"), A_PTR_IN("attrList"), A_PTR_OUT("attrBuf"),
            A_LEN("bufSize",2), A_INT("options") } },

  { .name="fgetattrlist", .surface=XF_SURFACE_BSD, .number=SYS_fgetattrlist, .nargs=5,
    .args={ A_FD("fd"), A_PTR_IN("attrList"), A_PTR_OUT("attrBuf"),
            A_LEN("bufSize",2), A_INT("options") } },

  { .name="kevent", .surface=XF_SURFACE_BSD, .number=SYS_kevent, .nargs=6,
    .args={ A_FD("kq"), A_PTR_IN("changelist"), A_INT("nchanges"),
            A_PTR_OUT("eventlist"), A_INT("nevents"), A_PTR_IN("timeout") } },

  { .name="shmget", .surface=XF_SURFACE_BSD, .number=SYS_shmget, .nargs=3,
    .args={ A_INT("key"), A_INT("size"), A_INT("shmflg") } },

  { .name="semget", .surface=XF_SURFACE_BSD, .number=SYS_semget, .nargs=3,
    .args={ A_INT("key"), A_INT("nsems"), A_INT("semflg") } },

  { .name="workq_open", .surface=XF_SURFACE_BSD, .number=SYS_workq_open, .nargs=0 },

  { .name="proc_info", .surface=XF_SURFACE_BSD, .number=SYS_proc_info, .nargs=6,
    .args={ A_INT("callnum"), A_INT("pid"), A_INT("flavor"),
            A_INT("arg"), A_PTR_OUT("buffer"), A_LEN("buffersize",4) } },

  { .name="csops", .surface=XF_SURFACE_BSD, .number=SYS_csops, .nargs=4,
    .args={ A_INT("pid"), A_INT("ops"), A_PTR_IO("useraddr"), A_LEN("usersize",2) } },

  { .name="fsctl", .surface=XF_SURFACE_BSD, .number=SYS_fsctl, .nargs=4,
    .args={ A_STR("path"), A_INT("cmd"), A_PTR_IO("data"), A_INT("options") } },

  { .name="ffsctl", .surface=XF_SURFACE_BSD, .number=SYS_ffsctl, .nargs=4,
    .args={ A_FD("fd"), A_INT("cmd"), A_PTR_IO("data"), A_INT("options") } },

  { .name="close", .surface=XF_SURFACE_BSD, .number=SYS_close, .nargs=1,
    .args={ A_FD("fd") } },
};

const xf_call_desc *xf_bsd_table(uint32_t *count) {
    *count = (uint32_t)XF_ARRAY_LEN(k_bsd);
    return k_bsd;
}

/* ----- Raw layer: cover every syscall number ----------------------------- *
 * Some numbers must never be issued raw because they act on the whole system
 * or the harness process in ways that defeat isolation. They are flagged
 * DANGEROUS and skipped in safe mode; the fork-isolated executor also runs
 * them in a child, but reboot/shutdown escape the child, hence the gate.
 */
static bool is_dangerous_syscall(uint32_t n) {
    switch (n) {
        case SYS_exit:            /* would kill the executor child early    */
        case SYS_fork:            /* fork bomb risk                          */
        case SYS_vfork:
        case SYS_reboot:          /* reboots the machine                     */
        case SYS_kill:            /* could signal the manager                */
        case SYS_shutdown:
        case SYS_unlink:
        case SYS_unlinkat:
        case SYS_rmdir:
        case SYS_execve:
        case SYS_posix_spawn:
        case SYS___mac_syscall:   /* sandbox/MAC policy churn                */
            return true;
        default:
            return false;
    }
}

/* Build heap-allocated raw descriptors for numbers 0..SYS_MAXSYSCALL-1.
 * Caller owns the returned array (never freed — lives for process lifetime). */
xf_call_desc *xf_bsd_build_raw(uint32_t *count) {
    const uint32_t maxsys = SYS_MAXSYSCALL;   /* 558 */
    xf_call_desc *tbl = calloc(maxsys, sizeof(*tbl));
    uint32_t n = 0;
    static char namebuf[558][24];
    for (uint32_t i = 0; i < maxsys; i++) {
        xf_call_desc *d = &tbl[n];
        snprintf(namebuf[i], sizeof(namebuf[i]), "sys_%u", i);
        d->name    = namebuf[i];
        d->surface = XF_SURFACE_BSD;
        d->number  = i;
        d->nargs   = 6;   /* over-provision; kernel ignores extra regs       */
        for (uint32_t a = 0; a < 6; a++) {
            d->args[a].type = XF_ARG_INT;
            d->args[a].name = "raw";
        }
        d->produces = XF_RES_NONE;
        d->flags    = is_dangerous_syscall(i) ? XF_C_DANGEROUS : XF_C_NONE;
        n++;
    }
    *count = n;
    return tbl;
}
