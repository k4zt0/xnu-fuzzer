/*
 * iokit_desc.c — IOKit user-client (Apple built-in driver) fuzzing surface.
 *
 * Discovery walks the IORegistry, finds every node exposing an
 * IOUserClientClass (i.e. an openable Apple driver user client), and probes a
 * small set of open-type selectors to see which actually open. Each openable
 * target becomes one xf_call_desc; the executor re-opens it by IORegistry
 * entry id inside the isolated child and drives IOConnectCallMethod against
 * fuzzed selectors and scalar/struct payloads — the path that reaches
 * IOUserClient::externalMethod in the kernel.
 */
#include "desc.h"
#include "iokit_target.h"
#include "log.h"

#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <string.h>
#include <stdlib.h>

xf_iokit_target g_iokit_targets[XF_IOKIT_MAX_TARGETS];
uint32_t        g_iokit_ntargets = 0;

static xf_call_desc *s_iokit_descs = NULL;
static uint32_t      s_iokit_ndescs = 0;

/* Clients whose mere use is destructive or reboots the box — skipped in
 * safe mode and deprioritized otherwise. */
static const char *k_dangerous_clients[] = {
    "AppleFDEKeyStoreUserClient", "AppleSEPUserClient",
    "AppleMobileFileIntegrityUserClient", "BootPolicyUserClient",
    "AppleFirmwareUpdateUserClient", "AppleSecureRepairUserClient",
    "EndpointSecurityDriverClient", "AppleCredentialManagerUserClient",
    "AppleKeyStoreUserClient", "AppleImage4UserClient",
    "AppleMobileApNonceUserClient", "AppleEpochManagerUserClient",
    /* Power management: a fuzzed method can sleep/shut down the machine.
     * Excluded in safe mode so autonomous runs don't knock the box out. */
    "RootDomainUserClient", "IOPMrootDomain",
};

static bool client_is_dangerous(const char *cls) {
    for (size_t i = 0; i < XF_ARRAY_LEN(k_dangerous_clients); i++)
        if (strcmp(cls, k_dangerous_clients[i]) == 0) return true;
    return false;
}

/* Read a CFString property into buf. */
static bool copy_str_prop(io_registry_entry_t e, CFStringRef key,
                          char *buf, size_t cap) {
    CFTypeRef v = IORegistryEntryCreateCFProperty(e, key, kCFAllocatorDefault, 0);
    bool ok = false;
    if (v && CFGetTypeID(v) == CFStringGetTypeID()) {
        ok = CFStringGetCString((CFStringRef)v, buf, cap, kCFStringEncodingUTF8);
    }
    if (v) CFRelease(v);
    return ok;
}

/* Number of open-type selectors to probe per node. Real drivers usually use
 * type 0; a few use 1..N. */
#define IOK_PROBE_TYPES 6
#define IOK_DEFAULT_MAX_SELECTOR 256

void xf_iokit_discover(void) {
    if (g_iokit_ntargets) return;   /* already discovered */

    io_iterator_t it = IO_OBJECT_NULL;
    kern_return_t kr = IORegistryCreateIterator(kIOMainPortDefault,
                                                kIOServicePlane,
                                                kIORegistryIterateRecursively,
                                                &it);
    if (kr != KERN_SUCCESS) {
        XF_WARN("IOKit: registry iterator failed: 0x%x", kr);
        return;
    }

    io_registry_entry_t e;
    uint32_t probed = 0, opened = 0;
    while ((e = IOIteratorNext(it)) && g_iokit_ntargets < XF_IOKIT_MAX_TARGETS) {
        char provider[128] = {0};
        IOObjectGetClass(e, provider);

        /* IOUserClientClass names the client the kernel will instantiate, when
         * the node advertises one; otherwise we fall back to the provider
         * class. We probe EVERY service node (not just ones exposing the
         * property) so openable Apple drivers that don't publish it are still
         * found. */
        char cls[128] = {0};
        if (!copy_str_prop(e, CFSTR("IOUserClientClass"), cls, sizeof(cls)))
            snprintf(cls, sizeof(cls), "%s", provider);
        probed++;

        uint64_t eid = 0;
        IORegistryEntryGetRegistryEntryID(e, &eid);

        bool danger = client_is_dangerous(cls);

        /* In safe mode we still record the target (for stats) but never open
         * destructive clients here. */
        bool found_open = false;
        if (!(g_cfg.safe_mode && danger)) {
            for (uint32_t t = 0; t < IOK_PROBE_TYPES; t++) {
                io_connect_t conn = IO_OBJECT_NULL;
                kr = IOServiceOpen(e, mach_task_self(), t, &conn);
                if (kr == KERN_SUCCESS && conn != IO_OBJECT_NULL) {
                    /* It opens — record and immediately close. */
                    xf_iokit_target *tg = &g_iokit_targets[g_iokit_ntargets++];
                    tg->entry_id     = eid;
                    tg->open_type    = t;
                    tg->max_selector = IOK_DEFAULT_MAX_SELECTOR;
                    tg->dangerous    = danger;
                    strncpy(tg->client_class, cls, sizeof(tg->client_class)-1);
                    strncpy(tg->provider, provider, sizeof(tg->provider)-1);
                    IOServiceClose(conn);
                    opened++;
                    found_open = true;
                    break;  /* one open-type is enough to make it a target   */
                }
            }
        }
        if (!found_open) {
            XF_DBG("IOKit: %s (provider %s) did not open", cls, provider);
        }
        IOObjectRelease(e);
    }
    IOObjectRelease(it);

    XF_INFO("IOKit discovery: %u user-client nodes probed, %u opens, %u targets",
            probed, opened, g_iokit_ntargets);
    for (uint32_t i = 0; i < g_iokit_ntargets; i++) {
        XF_INFO("  target[%u] %s (type=%u)%s", i,
                g_iokit_targets[i].client_class, g_iokit_targets[i].open_type,
                g_iokit_targets[i].dangerous ? " [dangerous]" : "");
    }
}

/* Build one descriptor per discovered target. */
static void build_descs(void) {
    if (s_iokit_descs) return;
    if (g_iokit_ntargets == 0) { s_iokit_ndescs = 0; return; }

    s_iokit_descs = calloc(g_iokit_ntargets, sizeof(*s_iokit_descs));
    static char namebuf[XF_IOKIT_MAX_TARGETS][160];

    for (uint32_t i = 0; i < g_iokit_ntargets; i++) {
        xf_call_desc *d = &s_iokit_descs[i];
        snprintf(namebuf[i], sizeof(namebuf[i]), "iokit:%s",
                 g_iokit_targets[i].client_class);
        d->name         = namebuf[i];
        d->surface      = XF_SURFACE_IOKIT;
        d->number       = 0;                 /* selector is an arg           */
        d->iokit_target = (int32_t)i;
        d->nargs        = XF_IOK_ARG_COUNT;
        d->flags        = g_iokit_targets[i].dangerous ? XF_C_DANGEROUS : XF_C_NONE;

        d->args[XF_IOK_ARG_SELECTOR] = (xf_arg_desc){
            .name="selector", .type=XF_ARG_INT };
        d->args[XF_IOK_ARG_SCALARS] = (xf_arg_desc){
            .name="scalars", .type=XF_ARG_BUFFER, .dir=XF_DIR_IN,
            .buf_min=0, .buf_max=128 /* up to 16 scalars */ };
        d->args[XF_IOK_ARG_STRUCT_IN] = (xf_arg_desc){
            .name="struct_in", .type=XF_ARG_BUFFER, .dir=XF_DIR_IN,
            .buf_min=0, .buf_max=4096 };
        d->args[XF_IOK_ARG_STRUCT_OUT] = (xf_arg_desc){
            .name="struct_out_size", .type=XF_ARG_INT };
    }
    s_iokit_ndescs = g_iokit_ntargets;
}

const xf_call_desc *xf_iokit_table(uint32_t *count) {
    build_descs();
    *count = s_iokit_ndescs;
    return s_iokit_descs;
}
