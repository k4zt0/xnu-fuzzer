/*
 * mach_desc.c — Mach trap interface descriptions for XNU arm64.
 *
 * Mach traps are invoked with a NEGATIVE trap number in x16 via `svc #0x80`
 * (see arch.h::xf_mach_trap). The numbers below are the stable arm64 trap
 * indices from XNU's osfmk/mach/syscall_sw.h. A handful act on global/host
 * state or other tasks and are gated behind safe-mode / NEEDS_ROOT.
 */
#include "desc.h"

/* Mach trap numbers are stored positive in `number`; the executor negates
 * them when issuing the trap. */
#define MT(n) (n)

static const uint64_t vmflags[] = { 0x0 /*fixed*/, 0x1 /*anywhere*/, 0x2 /*purgable*/ };
static const uint64_t vmprot[]  = { 0x1, 0x2, 0x3, 0x4, 0x7 };

#define A_INT(nm)     { .name=nm, .type=XF_ARG_INT }
#define A_PORT(nm)    { .name=nm, .type=XF_ARG_RESOURCE, .res_kind=XF_RES_MACHPORT }
#define A_PTR_IO(nm)  { .name=nm, .type=XF_ARG_PTR, .dir=XF_DIR_INOUT, .buf_min=0, .buf_max=256 }
#define A_PTR_IN(nm)  { .name=nm, .type=XF_ARG_PTR, .dir=XF_DIR_IN, .buf_min=0, .buf_max=256 }
#define A_FLG(nm,arr) { .name=nm, .type=XF_ARG_FLAGS, .flags=(arr), .flag_count=(uint32_t)XF_ARRAY_LEN(arr) }

static const xf_call_desc k_mach[] = {
  { .name="task_self_trap", .surface=XF_SURFACE_MACH, .number=MT(28), .nargs=0,
    .produces=XF_RES_MACHPORT },
  { .name="host_self_trap", .surface=XF_SURFACE_MACH, .number=MT(29), .nargs=0,
    .produces=XF_RES_MACHPORT },
  { .name="thread_self_trap", .surface=XF_SURFACE_MACH, .number=MT(27), .nargs=0,
    .produces=XF_RES_MACHPORT },
  { .name="mach_reply_port", .surface=XF_SURFACE_MACH, .number=MT(26), .nargs=0,
    .produces=XF_RES_MACHPORT },

  { .name="_kernelrpc_mach_port_allocate_trap", .surface=XF_SURFACE_MACH,
    .number=MT(16), .nargs=3,
    .args={ A_PORT("task"), A_INT("right"), A_PTR_IO("name") },
    .produces=XF_RES_MACHPORT },
  { .name="_kernelrpc_mach_port_deallocate_trap", .surface=XF_SURFACE_MACH,
    .number=MT(18), .nargs=2, .args={ A_PORT("task"), A_PORT("name") } },
  { .name="_kernelrpc_mach_port_mod_refs_trap", .surface=XF_SURFACE_MACH,
    .number=MT(19), .nargs=4,
    .args={ A_PORT("task"), A_PORT("name"), A_INT("right"), A_INT("delta") } },
  { .name="_kernelrpc_mach_port_insert_right_trap", .surface=XF_SURFACE_MACH,
    .number=MT(21), .nargs=4,
    .args={ A_PORT("task"), A_INT("name"), A_PORT("poly"), A_INT("polyPoly") } },
  { .name="_kernelrpc_mach_port_construct_trap", .surface=XF_SURFACE_MACH,
    .number=MT(24), .nargs=4,
    .args={ A_PORT("task"), A_PTR_IN("options"), A_INT("context"), A_PTR_IO("name") },
    .produces=XF_RES_MACHPORT },
  { .name="_kernelrpc_mach_port_destruct_trap", .surface=XF_SURFACE_MACH,
    .number=MT(25), .nargs=4,
    .args={ A_PORT("task"), A_PORT("name"), A_INT("srdelta"), A_INT("guard") } },
  { .name="_kernelrpc_mach_port_guard_trap", .surface=XF_SURFACE_MACH,
    .number=MT(41), .nargs=4,
    .args={ A_PORT("task"), A_PORT("name"), A_INT("guard"), A_INT("strict") } },

  { .name="_kernelrpc_mach_vm_allocate_trap", .surface=XF_SURFACE_MACH,
    .number=MT(10), .nargs=4,
    .args={ A_PORT("target"), A_PTR_IO("addr"), A_INT("size"), A_FLG("flags", vmflags) } },
  { .name="_kernelrpc_mach_vm_deallocate_trap", .surface=XF_SURFACE_MACH,
    .number=MT(12), .nargs=3,
    .args={ A_PORT("target"), A_INT("addr"), A_INT("size") } },
  { .name="_kernelrpc_mach_vm_protect_trap", .surface=XF_SURFACE_MACH,
    .number=MT(14), .nargs=5,
    .args={ A_PORT("target"), A_INT("addr"), A_INT("size"), A_INT("setmax"),
            A_FLG("prot", vmprot) } },
  { .name="_kernelrpc_mach_vm_map_trap", .surface=XF_SURFACE_MACH,
    .number=MT(15), .nargs=6,
    .args={ A_PORT("target"), A_PTR_IO("addr"), A_INT("size"), A_INT("mask"),
            A_FLG("flags", vmflags), A_FLG("prot", vmprot) } },

  { .name="mach_msg_trap", .surface=XF_SURFACE_MACH, .number=MT(31), .nargs=7,
    .args={ A_PTR_IO("msg"), A_INT("option"), A_INT("send_size"),
            A_INT("rcv_size"), A_PORT("rcv_name"), A_INT("timeout"), A_INT("notify") },
    .flags=XF_C_SLOW },
  { .name="mach_msg2_trap", .surface=XF_SURFACE_MACH, .number=MT(70), .nargs=8,
    .args={ A_PTR_IO("data"), A_INT("opt"), A_INT("msgh_bits"), A_INT("sz"),
            A_PORT("rcv"), A_INT("timeout"), A_INT("priority"), A_INT("dispatch") },
    .flags=XF_C_SLOW },

  { .name="semaphore_signal_trap", .surface=XF_SURFACE_MACH, .number=MT(33), .nargs=1,
    .args={ A_PORT("sema") } },
  { .name="semaphore_wait_trap", .surface=XF_SURFACE_MACH, .number=MT(36), .nargs=1,
    .args={ A_PORT("sema") }, .flags=XF_C_SLOW },

  { .name="mk_timer_create_trap", .surface=XF_SURFACE_MACH, .number=MT(91), .nargs=0,
    .produces=XF_RES_MACHPORT },
  { .name="mk_timer_arm_trap", .surface=XF_SURFACE_MACH, .number=MT(93), .nargs=2,
    .args={ A_PORT("name"), A_INT("expire_time") } },
  { .name="mk_timer_cancel_trap", .surface=XF_SURFACE_MACH, .number=MT(94), .nargs=2,
    .args={ A_PORT("name"), A_PTR_IO("result_time") } },
  { .name="mk_timer_destroy_trap", .surface=XF_SURFACE_MACH, .number=MT(92), .nargs=1,
    .args={ A_PORT("name") } },

  { .name="host_create_mach_voucher_trap", .surface=XF_SURFACE_MACH, .number=MT(70+2),
    .nargs=4,
    .args={ A_PORT("host"), A_PTR_IN("recipes"), A_INT("recipes_size"), A_PTR_IO("voucher") } },

  /* Privileged / cross-task — gated. */
  { .name="task_for_pid", .surface=XF_SURFACE_MACH, .number=MT(45), .nargs=3,
    .args={ A_PORT("target"), A_INT("pid"), A_PTR_IO("t") },
    .flags=XF_C_NEEDS_ROOT|XF_C_DANGEROUS },
  { .name="pid_for_task", .surface=XF_SURFACE_MACH, .number=MT(46), .nargs=2,
    .args={ A_PORT("t"), A_PTR_IO("pid") } },
  { .name="macx_swapon", .surface=XF_SURFACE_MACH, .number=MT(48), .nargs=4,
    .args={ A_INT("name"), A_INT("flags"), A_INT("size"), A_INT("priority") },
    .flags=XF_C_NEEDS_ROOT|XF_C_DANGEROUS },
};

const xf_call_desc *xf_mach_table(uint32_t *count) {
    *count = (uint32_t)XF_ARRAY_LEN(k_mach);
    return k_mach;
}
