# xfuzz — an XNU kernel fuzzer for Apple Silicon

`xfuzz` is a native, coverage-pluggable, generational fuzzer for the XNU kernel
on Apple Silicon (arm64) macOS, in the spirit of **syzkaller**, **AFL**, and
**NTFUZZ** but built around XNU's actual attack surfaces and the realities of a
stock, SIP-enabled machine. It runs directly against the live kernel of the
system it's installed on, evolves a corpus of interesting programs, and survives
the kernel panics it is designed to provoke.

> ⚠️ **This tool fuzzes the running kernel. It can and will panic/reboot the
> machine.** That is the point. Run it on a machine you can afford to crash, or
> under the reboot-surviving LaunchDaemon (below) so it self-resumes and records
> reproducers across reboots.

## Attack surfaces

| Surface | What it hits | Notes |
|---|---|---|
| **BSD syscalls** | `syscall(2)` entry points 0..557 | Curated typed table (fd-producing sequences: `open`→`ioctl`→…) **plus** a raw layer covering every syscall number. |
| **Mach traps** | arm64 negative-numbered traps (`svc #0x80`) | VM, port, semaphore, timer, voucher traps. |
| **IOKit** | `IOConnectCallMethod` → `IOUserClient::externalMethod` | Discovers openable **Apple built-in driver** user clients and fuzzes selectors + scalar/struct payloads. Most Apple user clients require **root** to open (see below). |

## Architecture

```
             ┌─────────────┐   descriptions   ┌──────────────┐
 generator ──│  registry   │◀─────────────────│ bsd/mach/iokit│
   mutator ──│ (desc.c)    │                  │  desc tables  │
             └─────┬───────┘                  └──────────────┘
                   │ programs (prog.c: typed calls, resources)
                   ▼
             ┌─────────────┐  fork + timeout   ┌──────────────┐
  scheduler ─│  executor   │──────────────────▶│ LIVE  KERNEL │
   (main.c)  │ (isolated)  │◀─ exit/signal ────│  (arm64 XNU) │
             └─────┬───────┘                   └──────┬───────┘
                   │ corpus (novelty oracle)          │ panic
                   ▼                                  ▼
             ┌─────────────┐                   ┌──────────────┐
             │   corpus/   │                   │ crash monitor│
             │  faults/    │                   │  + persist   │◀ reboot
             └─────────────┘                   └──────────────┘
```

- **Program model** (`prog.{h,c}`): a program is a sequence of typed calls with
  arguments and *resources* (fds, mach ports, IOKit connections) threaded
  between calls, so the fuzzer builds semantically valid sequences. Programs
  serialize to a compact, diffable text form.
- **Executor** (`executor.c`): each program runs in a fresh `fork()`. The child
  **seals inherited fds** (so fuzzed fd syscalls can't corrupt the manager) and
  **chdir**s into a throwaway sandbox (so fuzzed file creation can't litter the
  tree). A per-call `SIGALRM` (20 ms) interrupts benign blocking; a
  `sigsetjmp`/`siglongjmp` recovery point lets a fatal signal skip only the
  faulting call so multi-call programs run to completion. The parent enforces a
  wall-clock timeout as the hang backstop.
- **Triage**: userspace arg-faults (SIGSEGV/SIGSYS/… in the child) are **benign
  telemetry**, not kernel bugs — deduplicated samples land in `faults/`. The
  real oracles are **kernel panics** (out of band) and **hangs** (timeouts).
- **Coverage** (`coverage.c`): pluggable and KCOV-shaped. Stock SIP kernels
  expose no edge coverage, so the default backend is **blind** (crash/hang
  oracle + a coarse novelty heuristic). A **kdebug** backend (root, coarse) can
  be plugged in; a real edge-coverage source drops in unchanged.
- **Crash / persistence** (`crash.c`, `persist.c`): a `pending` marker is
  written before each execution; after a panic+reboot the daemon scans
  `/Library/Logs/DiagnosticReports/Kernel-*.ips` (and `nvram panicinfo`),
  attributes the panic to the pending program, and saves a reproducer.

## Build

```sh
make                 # -> ./xfuzz   (links IOKit + CoreFoundation)
```

## Run

```sh
# Validate the engine without touching the kernel:
./xfuzz --dry-run --max-execs 20000

# Safe live fuzzing of BSD + Mach (default surfaces, non-destructive gating):
./xfuzz --surfaces bsd,mach --procs 5

# Full Apple-driver (IOKit) fuzzing needs root to open most user clients:
sudo ./xfuzz --surfaces iokit,bsd,mach --unsafe --procs 4
```

Key flags: `--procs N` (parallel workers), `--timeout MS`, `--surfaces`,
`--cov blind|kdebug`, `--unsafe` (allow DANGEROUS-flagged calls; the executor
still never issues `reboot`/`exec`), `--dry-run`, `--max-execs N`.

Outputs (under `--workdir`, default `./run`): `corpus/`, `crashes/` (hangs +
panic reproducers), `faults/` (deduped benign-fault samples), `state/`
(pending marker + counter), `sandbox/` (throwaway child cwd), `xfuzz.log`.

## Reboot-surviving deployment (root)

```sh
sudo scripts/install_daemon.sh        # installs + bootstraps the LaunchDaemon
sudo launchctl bootout system/com.xfuzz.fuzzer   # stop
```

The daemon runs as root (unlocking most Apple driver user clients), persists
state in `/var/root/xfuzz`, and auto-resumes after each panic, recording the
culprit program as a reproducer.

## Realities on a stock, SIP-enabled Apple Silicon Mac

- **No KCOV / no deterministic edge coverage.** Genuine block/edge coverage
  needs SIP off + an instrumented kernel. `xfuzz` is designed to run blind and
  still find panics, with pluggable coverage for when a signal is available.
- **Most Apple IOKit user clients require root or entitlements.** As a normal
  user only a handful open. Run under the root daemon for the real Apple-driver
  surface.
- **Non-root is itself a safety boundary**: system-mutating syscalls return
  `EPERM`, so much of the BSD surface can be exercised without wrecking the box.
