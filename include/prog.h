/*
 * prog.h — the program model and interface-description schema.
 *
 * A *program* (xf_prog) is an ordered sequence of *calls*. Each call targets
 * one entry in an interface-description table (xf_call_desc) — a BSD syscall,
 * a Mach trap, or an IOKit external method — and carries typed *arguments*
 * (xf_arg). Calls can produce *resources* (a returned fd, mach port, or IOKit
 * connection) that later calls consume, so the fuzzer builds semantically
 * meaningful sequences (open -> ioctl -> close) rather than isolated calls.
 *
 * This mirrors syzkaller's prog/description split: descriptions are static
 * metadata; programs are the mutable, serializable units the engine evolves.
 */
#ifndef XF_PROG_H
#define XF_PROG_H

#include "xfuzz.h"
#include "rng.h"

/* ----- Argument type schema ---------------------------------------------- */
typedef enum {
    XF_ARG_CONST = 0,   /* fixed immediate value                            */
    XF_ARG_INT,         /* fuzzed integer (uses interesting-value pool)     */
    XF_ARG_FLAGS,       /* bitmask OR of entries from a flag set            */
    XF_ARG_LEN,         /* length of a referenced buffer arg (auto-filled)  */
    XF_ARG_PTR,         /* pointer to an in/out/inout buffer                */
    XF_ARG_STRING,      /* pointer to a C string / filename                 */
    XF_ARG_RESOURCE,    /* consumes a resource produced by an earlier call  */
    XF_ARG_BUFFER,      /* inline byte blob (also produces a pointer)       */
    XF_ARG_TYPE_COUNT
} xf_argtype_t;

/* Direction of a pointer's payload w.r.t. the kernel. */
typedef enum { XF_DIR_IN = 0, XF_DIR_OUT, XF_DIR_INOUT } xf_dir_t;

/* Resource kinds — what a call can produce/consume. */
typedef enum {
    XF_RES_NONE = 0,
    XF_RES_FD,          /* file descriptor                                  */
    XF_RES_MACHPORT,    /* mach_port_t                                      */
    XF_RES_IOCONN,      /* io_connect_t (IOKit user client)                 */
    XF_RES_PID,
    XF_RES_KIND_COUNT
} xf_reskind_t;

/* ----- Static description of one argument -------------------------------- */
typedef struct {
    const char    *name;
    xf_argtype_t   type;
    xf_reskind_t   res_kind;    /* for RESOURCE args                        */
    xf_dir_t       dir;         /* for PTR/BUFFER args                       */
    uint64_t       const_val;   /* for CONST args                           */
    const uint64_t*flags;       /* for FLAGS args: table of candidate bits  */
    uint32_t       flag_count;
    uint32_t       len_ref;     /* for LEN args: index of the buffer arg    */
    uint32_t       buf_min, buf_max; /* for PTR/BUFFER byte range           */
} xf_arg_desc;

/* Call-level metadata flags. */
enum {
    XF_C_NONE      = 0,
    XF_C_DANGEROUS = 1u << 0,   /* reboot/unlink/kill — gated by safe_mode   */
    XF_C_SLOW      = 1u << 1,   /* may block; executor uses shorter timeout  */
    XF_C_NEEDS_ROOT= 1u << 2,
};

/* ----- Static description of one call ------------------------------------ */
typedef struct {
    const char    *name;
    xf_surface_t   surface;
    uint32_t       number;      /* syscall/trap number; method sel for IOKit */
    uint32_t       nargs;
    xf_arg_desc    args[XF_MAX_ARGS];
    xf_reskind_t   produces;    /* resource kind the return value yields     */
    uint32_t       flags;       /* XF_C_*                                    */
    /* IOKit only: index into the iokit target table this method belongs to. */
    int32_t        iokit_target;
} xf_call_desc;

/* ----- Concrete (mutable) argument value --------------------------------- */
typedef struct {
    xf_argtype_t type;
    uint64_t     val;           /* immediate, or resource slot for RESOURCE  */
    /* For PTR/BUFFER/STRING: an inline payload materialized at exec time.   */
    uint8_t     *blob;
    uint32_t     blob_len;
} xf_arg;

/* ----- Concrete call ----------------------------------------------------- */
typedef struct {
    const xf_call_desc *desc;   /* points into a static table                */
    uint32_t     desc_id;       /* stable id for (de)serialization           */
    xf_arg       args[XF_MAX_ARGS];
    uint32_t     nargs;
    int32_t      res_slot;      /* resource slot this call writes (-1 none)  */
    uint64_t     result;        /* filled at exec time                       */
    int          err;           /* errno / kern_return_t captured            */
} xf_call;

/* ----- Program ----------------------------------------------------------- */
typedef struct {
    xf_call   calls[XF_MAX_CALLS];
    uint32_t  ncalls;
    /* Resource pool: slot -> concrete value (fd/port/conn) at exec time. */
    uint64_t  res_vals[XF_MAX_RESOURCES];
    xf_reskind_t res_kind[XF_MAX_RESOURCES];
    uint32_t  nres;
} xf_prog;

/* ----- Lifecycle --------------------------------------------------------- */
void xf_prog_init(xf_prog *p);
void xf_prog_free(xf_prog *p);            /* frees arg blobs                 */
void xf_prog_copy(xf_prog *dst, const xf_prog *src);

/* Serialize to a compact, human-diffable text form (like syzkaller progs).
 * Returns number of bytes written (excluding NUL). */
size_t xf_prog_serialize(const xf_prog *p, char *out, size_t cap);

/* Parse the text form back into a program. Returns true on success. */
bool   xf_prog_deserialize(xf_prog *p, const char *text);

#endif /* XF_PROG_H */
