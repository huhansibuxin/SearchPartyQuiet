// SearchPartyQuiet v1.0.2 - block useless ObservationStore writes in searchpartyd
//                            arm64e / roothide only
// =============================================================================
// WHAT THIS DOES
//   searchpartyd burns 50-93% CPU for 1-10 s roughly every 15 minutes. Root
//   cause (2h htop + fs_usage, 2026-11-15): a batch of Beacon observations is
//   written into a 263 MB SQLCipher DB (Observations.db) that is ~91% dead
//   pages; the 4 MB WAL checkpoint then has to merge into that bloated file.
//   The user has Find My / "Find My Network" DISABLED (UserOptOut) - these
//   observation writes are pure background garbage with zero user value.
//
//   We hook, inside searchpartyd ONLY, the arm64e auth-GOT slot of
//     _sqlite3_step  (slot 1226 -> vm 0x100e12650).
//   On each step we read the statement's SQL via sqlite3_sql() (linked from
//   libsqlite3, resolved OUR dylib's symbols - never through this GOT slot).
//   If it is an INSERT/REPLACE into a known observation table we return
//   SQLITE_DONE (101) WITHOUT calling the original: no row is written, the
//   WAL stops growing, and the checkpoint storms disappear.
//
//   DELETE / UPDATE / PRAGMA / SELECT / everything else is ALWAYS passed
//   through. In particular the built-in prune + `PRAGMA incremental_vacuum`
//   (symbols PruneObservationStoreService / incrementalVacuum in the binary)
//   keep running, so existing dead pages can still be reclaimed.
//
// WHY A SINGLE HOOK, GOT REBIND, NOT ObjC / NOT CONFIG
//   - The write path is pure C through libsqlite3 (externally linked, verified
//     in LC_LOAD_DYLIB), not reachable via class_replaceMethod.
//   - ONE slot only. searchpartyd crashed 25x on 11-14 (Swift _assertionFailure
//     in BeaconKeyManager, NO third-party dylib in those IPS - caused by
//     mutating config/data). Minimal surface + fail-open is the red line.
//   - Editing savedConfiguration.plist is USELESS: cfprefsd caches the domain
//     and layers[1]/[4] get rebuilt. So this tweak NEVER writes a plist, NEVER
//     touches a DB file, NEVER changes Swift state. It only makes step() report
//     "insert succeeded" for a write that never reaches disk.
//
// PAC SAFETY (the CacheDeleteQuiet v1.2.0 crash, never repeat)
//   arm64e function-pointer calls compile to `blraaz x8` (ASIA, modifier 0).
//   A ptrauth_strip()ped pointer stored as "original" fails that auth and
//   kills the process on first call. We therefore:
//     - read dyld's already-signed slot pointer,
//     - verify its discriminator numerically (no deref, no branch to it),
//     - re-sign the stripped original with sign_unauthenticated(..., IA, 0),
//     - prove a round trip, reject self-referential slots (double ctor),
//     - only then vm_protect(VM_PROT_COPY) and swap in a freshly signed wrapper.
//   Any uncertainty => fail-open (slot untouched, zero behaviour change).
//
// LAYOUT (verified offline by sqlite_slot_probe.py on the shipped binary)
//   Mach-O: arm64e (subtype 0x80000002), LC_DYLD_CHAINED_FIXUPS, main exe.
//   __TEXT vm=0x100000000 ; __DATA_CONST vm=0x100e10000 file=0xe10000.
//   __auth_got vm=0x100e10000 file=0xe10000, DENSE: slot = base + 8*ordinal.
//     _sqlite3_step : ordinal 1225 -> slot 1226 -> vm 0x100e12650
//   Runtime slot address = mh_base + (slotVm - textVm); mh_base is the
//   mach_header address (== __TEXT vmaddr + slide). Never a hardcoded absolute.
//
// MODES (empty flag files, checked ONCE in ctor, then kickstart -k)
//   (none)            QUIET  - skip observation INSERTs [default]
//   PROBE_ONLY        probe  - rebind + log every INSERT, but call original
//   PASSTHROUGH_ALL   pass   - no rebind at all, stock behaviour
//   DISABLED          off    - no constructor work at all
//   Log (first writable wins - a single hardcoded path silently fails):
//     $TMPDIR/SearchPartyQuiet.log
//     /var/mobile/Documents/SearchPartyQuiet/quiet.log
//     /var/mobile/Library/Logs/SearchPartyQuiet.log
//     /var/tmp/SearchPartyQuiet.log            <-- real one on device
//     /private/var/tmp/SearchPartyQuiet.log
//   With SSH prepend /rootfs/private. Flags may be dropped in any of those dirs.
//
// HARD CONSTRAINTS
//   - ZERO Logos %hook / ZERO substrate / ZERO ellekit LINK dependency.
//   - Link libsqlite3 (for sqlite3_sql only), libSystem, ptrauth builtins.
//     NO Foundation / UIKit. NO Logos runtime.
//   - NO polling / timer / dispatch_after. Event-driven only.
//   - NO writes to any config plist or database file. Read-only on data.
//   - Fail-open on missing slot / unmatched PAC discriminator / crash loop.
// =============================================================================

#import <stdint.h>
#import <stdlib.h>
#import <stdarg.h>
#import <string.h>
#import <stdio.h>
#import <unistd.h>
#import <fcntl.h>
#import <errno.h>
#import <time.h>
#import <sys/stat.h>
#import <sys/time.h>
#import <mach/mach.h>
#import <mach/machine.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <dlfcn.h>
#import <sqlite3.h>

#if __has_include(<ptrauth.h>)
#import <ptrauth.h>
#define SPQ_PTRAUTH 1
#else
#define SPQ_PTRAUTH 0
#endif

// CI asserts this exact build tag is present in the dylib.
static const char kBuildTag[] __attribute__((used)) =
    "SearchPartyQuiet 1.0.2 QUIET auth-got-rebind observation-insert-skip roothide-only";

#define kFlagDir        "/var/mobile/Documents/SearchPartyQuiet"
#define kFlagOff        kFlagDir "/DISABLED"
#define kFlagPass       kFlagDir "/PASSTHROUGH_ALL"
#define kFlagProbe      kFlagDir "/PROBE_ONLY"
#define kStatePath      "/private/var/tmp/SearchPartyQuiet.state"

static const char *kLogCandidates[] = {
    "/var/mobile/Documents/SearchPartyQuiet/quiet.log",
    "/var/mobile/Library/Logs/SearchPartyQuiet.log",
    "/var/tmp/SearchPartyQuiet.log",
    "/private/var/tmp/SearchPartyQuiet.log",
};
static const char *kLogDirs[] = {
    "/var/mobile/Documents/SearchPartyQuiet",
    "/var/mobile/Library/Logs",
    "/var/tmp",
    "/private/var/tmp",
};
#define kCandCount (sizeof(kLogCandidates) / sizeof(kLogCandidates[0]))

enum { MODE_OFF = 0, MODE_QUIET = 1, MODE_PROBE = 2, MODE_PASS = 3 };

static int g_mode = MODE_QUIET;
static int g_logfd = -1;
static const char *g_logpath = "(none)";
static int g_openErrno[4] = {0, 0, 0, 0};

// ---- tiny libSystem-only logger -------------------------------------------
static unsigned long long now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, 0);
    return (unsigned long long)tv.tv_sec * 1000ULL + (unsigned long long)(tv.tv_usec / 1000);
}

static void plog(const char *fmt, ...) {
    if (g_logfd < 0) return;
    char body[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (n > (int)sizeof(body) - 1) n = (int)sizeof(body) - 1;

    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    char ts[32];
    strftime(ts, sizeof(ts), "%F %T", &tm);

    char line[1152];
    int m = snprintf(line, sizeof(line), "[%s] %.*s\n", ts, n, body);
    if (m <= 0) return;
    if (m > (int)sizeof(line) - 1) m = (int)sizeof(line) - 1;
    (void)write(g_logfd, line, (size_t)m);
}

static char g_dynLog[512];

static void open_log(void) {
    const char *tmp = getenv("TMPDIR");
    if (tmp && *tmp) {
        int n = snprintf(g_dynLog, sizeof(g_dynLog), "%s/SearchPartyQuiet.log", tmp);
        if (n > 0 && n < (int)sizeof(g_dynLog)) {
            int fd = open(g_dynLog, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (fd >= 0) { g_logfd = fd; g_logpath = g_dynLog; return; }
        }
    }
    for (size_t i = 0; i < kCandCount; i++) {
        (void)mkdir(kLogDirs[i], 0755);
        int fd = open(kLogCandidates[i], O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) { g_logfd = fd; g_logpath = kLogCandidates[i]; return; }
        g_openErrno[i] = errno;
    }
}

static int flag_exists(const char *name) {
    static const char *dirs[] = {
        "/var/mobile/Documents/SearchPartyQuiet",
        "/var/mobile/Library/Logs",
        "/var/tmp",
        "/private/var/tmp",
    };
    const char *tmp = getenv("TMPDIR");
    if (tmp && *tmp) {
        char p[512];
        int n = snprintf(p, sizeof(p), "%s/%s", tmp, name);
        if (n > 0 && n < (int)sizeof(p)) {
            struct stat st;
            if (stat(p, &st) == 0) return 1;
        }
    }
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        char p[256];
        int n = snprintf(p, sizeof(p), "%s/%s", dirs[i], name);
        if (n > 0 && n < (int)sizeof(p)) {
            struct stat st;
            if (stat(p, &st) == 0) return 1;
        }
    }
    return 0;
}

// v1.0.0 crash-loop breaker: 4 starts inside 5 min => we are crash-looping,
// so drop the rebind entirely (everything becomes stock SQLite). 11-14 this
// daemon crashed 25x; this is the hard safety net. Delete the state to re-arm.
static int spq_guard_rapid_restart(void) {
    time_t now = time(NULL);
    char buf[256];
    int n = 0;
    int fd = open(kStatePath, O_RDONLY);
    if (fd >= 0) {
        n = (int)read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n < 0) n = 0;
    }
    buf[n] = 0;
    int recent = 0, total = 0;
    const char *p = buf;
    while (*p && total < 32) {
        while (*p && (*p < '0' || *p > '9')) p++;
        if (!*p) break;
        long long v = 0;
        while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
        total++;
        if (now - (time_t)v <= 300) recent++;
    }
    int flags = O_WRONLY | O_CREAT | O_APPEND;
    if (total >= 16) flags |= O_TRUNC;
    fd = open(kStatePath, flags, 0600);
    if (fd >= 0) {
        char line[32];
        int m = snprintf(line, sizeof(line), "%lld\n", (long long)now);
        if (m > 0) (void)write(fd, line, (size_t)m);
        close(fd);
    }
    return recent >= 3;
}

// ---- SQL classification ----------------------------------------------------
static int ci_prefix(const char *s, const char *pfx) {
    if (!s || !pfx) return 0;
    while (*pfx) {
        if (!*s) return 0;
        unsigned char a = (unsigned char)*s, b = (unsigned char)*pfx;
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return 0;
        s++; pfx++;
    }
    return 1;
}
static int ci_contains(const char *s, const char *needle) {
    if (!s || !needle || !*needle) return 0;
    for (const char *p = s; *p; p++)
        if (ci_prefix(p, needle)) return 1;
    return 0;
}

// Which INSERTs count as "useless observation writes"?
//   Deliberately conservative: BOTH an INSERT/REPLACE prefix AND a known
//   observation table name must match. Everything else (CloudKit / key
//   records / settings / any DELETE-UPDATE-PRAGMA-SELECT) passes through.
//   The binary logs "Error inserting observedAdvertisement"; the store class
//   is BeaconObservationStore and the DB file is Observations.db.
static int is_quiet_insert(const char *sql) {
    if (!sql) return 0;
    while (*sql == ' ' || *sql == '\t' || *sql == '\n' || *sql == '\r') sql++;
    if (!(ci_prefix(sql, "insert") || ci_prefix(sql, "replace"))) return 0;
    static const char *kTables[] = {
        "observedadvertisement",
        "observed_advertisement",
        "beaconobservation",
        "beacon_observation",
        "observation",
        "observations",
        "locationprovider",
        "beaconestimatedlocation",
    };
    for (size_t i = 0; i < sizeof(kTables) / sizeof(kTables[0]); i++)
        if (ci_contains(sql, kTables[i])) return 1;
    return 0;
}

// =============================================================================
// arm64e auth-GOT rebind of ONE slot: _sqlite3_step.
// PAC-safe flow copied from CacheDeleteQuiet v1.3.0 (proven crash-free).
// =============================================================================
// slot VM = 0x100e12650 (ordinal 1225 -> slot 1226), __DATA_CONST vm=0x100e10000.
#define SPQ_STEP_SLOT_VM 0x100e12650ULL
#define SPQ_TEXT_VM      0x100000000ULL

// int sqlite3_step(sqlite3_stmt*)
typedef int (*fn_step)(void *);

// g_origStep MUST hold a PAC-signed pointer (IA key, modifier 0): the call
// `f(stmt)` compiles to `blraaz x8`. See crash note in header.
static void *g_origStep = NULL;
static int g_bound = 0;
static unsigned long long g_stepTotal = 0, g_stepSkipped = 0, g_stepPass = 0;
static unsigned long long g_quietLogN = 0;

static int spq_wrap_step(void *stmt) {
    __sync_fetch_and_add(&g_stepTotal, 1ULL);
    fn_step f = (fn_step)g_origStep;
    if (!f) return 101; // no original -> fail closed for this call only (never crash)

    const char *sql = sqlite3_sql((sqlite3_stmt *)stmt);
    if (sql && is_quiet_insert(sql)) {
        __sync_fetch_and_add(&g_stepSkipped, 1ULL);
        if (g_mode == MODE_PROBE) {
            // A/B baseline: log what WOULD be skipped, but write it.
            if ((g_quietLogN++ & 0xFFULL) == 0)
                plog("PROBE would-skip sql=%.*s\n", (int)strnlen(sql, 180), sql);
            return f(stmt);
        }
        if ((g_stepSkipped & 0x3FULL) == 1)
            plog("SKIP sql=%.*s skipped=%llu\n", (int)strnlen(sql, 180), sql, g_stepSkipped);
        // SQLITE_DONE: for an INSERT this is the normal success result, so the
        // Swift caller sees no error and no row ever reaches disk/WAL.
        return 101;
    }

    __sync_fetch_and_add(&g_stepPass, 1ULL);
    if ((g_stepTotal & 0xFFFFULL) == 0 && g_stepTotal)
        plog("STAT total=%llu skipped=%llu pass=%llu\n",
             g_stepTotal, g_stepSkipped, g_stepPass);
    return f(stmt);
}

#if SPQ_PTRAUTH
static int spq_verify_disc(void *signedPtr, void *slotAddr, void *stripped,
                            uint64_t *discOut) {
    uint64_t d1 = (uint64_t)(uintptr_t)slotAddr;      // stub passes x17 = slot
    if (ptrauth_auth_data(signedPtr, ptrauth_key_asia, d1) == stripped) {
        *discOut = d1; return 1;
    }
    uint64_t d2 = (uint64_t)(uintptr_t)ptrauth_blend_discriminator(slotAddr, 0ULL);
    if (ptrauth_auth_data(signedPtr, ptrauth_key_asia, d2) == stripped) {
        *discOut = d2; return 2;
    }
    if (ptrauth_auth_data(signedPtr, ptrauth_key_asia, 0ULL) == stripped) {
        *discOut = 0ULL; return 3;
    }
    return 0;
}
#endif

// Locate the main searchpartyd image by name (NOT image 0 - an injected dylib
// can own index 0 under roothide; see CacheDeleteQuiet v1.1.0 lesson).
static const struct mach_header_64 *spq_locate_image(uint8_t **baseOut) {
    uint32_t n = _dyld_image_count();
    const struct mach_header_64 *byName = NULL, *byExec = NULL;
    plog("IMG count=%u\n", n);
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        const struct mach_header_64 *h =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        int hot = nm && strstr(nm, "searchpartyd");
        if (i < 16 || hot)
            plog("IMG [%u] mh=%p %s\n", i, (void *)h, nm ? nm : "?");
        if (hot) byName = h;
        if (h && h->magic == MH_MAGIC_64 && h->filetype == MH_EXECUTE && !byExec)
            byExec = h;
    }
    const struct mach_header_64 *mh = byName ? byName : byExec;
    plog("IMG PICK byName=%p byExec=%p -> %p\n", (void *)byName, (void *)byExec, (void *)mh);
    *baseOut = (uint8_t *)mh;
    return mh;
}

static int spq_install_hook(void) {
#if !SPQ_PTRAUTH
    plog("REBIND MISS ptrauth.h unavailable (not arm64e)\n");
    return 0;
#else
    uint8_t *base = NULL;
    const struct mach_header_64 *mh = spq_locate_image(&base);
    if (!mh || mh->magic != MH_MAGIC_64 || mh->cputype != CPU_TYPE_ARM64) {
        plog("REBIND MISS bad main image header\n");
        return 0;
    }
    uint64_t textVm = 0, dcVm = 0;
    const uint8_t *p = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize < 8) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)p;
            if (!strncmp(sg->segname, "__TEXT", 6)) textVm = sg->vmaddr;
            else if (!strncmp(sg->segname, "__DATA_CONST", 12)) dcVm = sg->vmaddr;
        }
        p += lc->cmdsize;
    }
    plog("SEG textVm=0x%llX dcVm=0x%llX (expect 0x100000000 / 0x100e10000)\n",
         (unsigned long long)textVm, (unsigned long long)dcVm);
    if (!textVm || !dcVm) { plog("REBIND MISS no __TEXT/__DATA_CONST\n"); return 0; }

    uint64_t slotVm = SPQ_STEP_SLOT_VM;
    // mh_base == __TEXT vmaddr + slide. Runtime slot = mh_base + (slotVm - textVm).
    // Verify the offset stays inside __DATA_CONST before touching it.
    if (slotVm < dcVm || (slotVm - dcVm) >= 0x60000ULL) {
        plog("REBIND MISS slotVm 0x%llX outside __DATA_CONST\n", (unsigned long long)slotVm);
        return 0;
    }
    void **slot = (void **)(base + (slotVm - textVm));
    void *signedPtr = *slot;
    void *stripped = ptrauth_strip(signedPtr, ptrauth_key_asia);
    uintptr_t addr = (uintptr_t)stripped;
    plog("SLOT sqlite3_step addr=%p raw=0x%016llX stripped=0x%llX\n",
         (void *)slot, (unsigned long long)(uintptr_t)signedPtr,
         (unsigned long long)addr);
    if (addr < 0x100000000ULL || addr > 0x0000800000000000ULL) {
        plog("REBIND MISS not code (fail-open)\n");
        return 0;
    }
    // Compare against the STRIPPED wrapper address: the raw (void*)fn here is
    // pre-signed (PAC bits), while `addr` came from ptrauth_strip(). Comparing
    // the two would never match and a double ctor would self-hook -> crash.
    if (addr == (uintptr_t)ptrauth_strip((void *)spq_wrap_step, ptrauth_key_asia)) {
        plog("REBIND SKIP already-ours (double ctor, fail-open)\n");
        return 0;
    }

    uint64_t disc = 0;
    int which = spq_verify_disc(signedPtr, (void *)slot, stripped, &disc);
    if (!which) { plog("REBIND MISS pac-disc unverified (fail-open)\n"); return 0; }

    void *signedOrig = ptrauth_sign_unauthenticated(stripped, ptrauth_key_asia, 0);
    if (ptrauth_auth_data(signedOrig, ptrauth_key_asia, 0) != stripped) {
        plog("REBIND MISS orig re-auth round-trip failed (fail-open)\n");
        return 0;
    }
    g_origStep = signedOrig;

    long pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize <= 0) pagesize = 16384;
    vm_address_t page = (vm_address_t)((uintptr_t)slot & ~(uintptr_t)(pagesize - 1));
    kern_return_t kr = vm_protect(mach_task_self(), page, (vm_size_t)pagesize, 0,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        plog("REBIND MISS vm_protect kr=%d (fail-open)\n", (int)kr);
        g_origStep = NULL; return 0;
    }
    // v1.0.2 CRASH FIX: `spq_wrap_step` used here as (void*) is an arm64e
    // FUNCTION POINTER CONSTANT - clang emits it ALREADY SIGNED (IA, mod 0).
    // Device v1.0.1 log proved it: wrap=0x8b440001040250e8 (PAC=0x8b44 baked in).
    // Feeding that pre-signed value to ptrauth_sign_unauthenticated() produces
    // a double-signed pointer with garbage PAC. Callers use `braa x16, x17`
    // (x17 = slot), auth fails at wrapper entry -> EXC_BAD_ACCESS / PAC fault on
    // the very first step (3/3 IPS at 23:02:30, FR0 = wrapper dylib+0x50e8).
    // CacheDeleteQuiet's array-of-wrappers worked because array elements are
    // stripped data pointers; our direct (void*)fn was pre-signed. FIX: strip
    // the function pointer to its raw address FIRST, then sign with `disc`,
    // and prove the round trip numerically BEFORE writing to the GOT.
    void *wrapRaw = ptrauth_strip((void *)spq_wrap_step, ptrauth_key_asia);
    void *newSigned = ptrauth_sign_unauthenticated(wrapRaw, ptrauth_key_asia, disc);
    if (ptrauth_auth_data(newSigned, ptrauth_key_asia, disc) != wrapRaw) {
        plog("REBIND MISS wrapper re-auth round-trip failed (fail-open)\n");
        g_origStep = NULL;
        (void)vm_protect(mach_task_self(), page, (vm_size_t)pagesize, 0, VM_PROT_READ);
        return 0;
    }
    *slot = newSigned;
    (void)vm_protect(mach_task_self(), page, (vm_size_t)pagesize, 0, VM_PROT_READ);
    g_bound = 1;
    plog("REBIND OK slot=%p orig=0x%llX wrapRaw=%p signed=%p disc=%d mode=%d\n",
         (void *)slot, (unsigned long long)addr, wrapRaw, newSigned, which, g_mode);
    return 1;
#endif
}

// ---- ctor -----------------------------------------------------------------
__attribute__((constructor)) static void spq_init(void) {
    if (flag_exists("DISABLED")) return;

    g_mode = MODE_QUIET;
    if (flag_exists("PROBE_ONLY"))           g_mode = MODE_PROBE;
    else if (flag_exists("PASSTHROUGH_ALL")) g_mode = MODE_PASS;

    open_log();
    plog("START %llu build=1.0.2 mode=%d pid=%d uid=%d proc=searchpartyd log=%s "
         "errno=[%d,%d,%d,%d] logfd=%d\n",
         now_ms(), g_mode, (int)getpid(), (int)getuid(), g_logpath,
         g_openErrno[0], g_openErrno[1], g_openErrno[2], g_openErrno[3], g_logfd);

    if (g_mode == MODE_PASS) { plog("REBIND SKIPPED mode=PASSTHROUGH_ALL (stock SQLite)\n"); return; }

    int guard = spq_guard_rapid_restart();
    plog("GUARD rapid-restart=%d (4 starts/5min trips it; delete %s to re-arm)\n", guard, kStatePath);
    if (guard) { plog("REBIND SKIPPED guard=crash-loop -> stock SQLite (safe)\n"); return; }

    (void)spq_install_hook();
    plog("READY bound=%d mode=%d hooked=_sqlite3_step(slot1226,0x100e12650) "
         "readvia=sqlite3_sql quiet-tables=observedadvertisement,observation,"
         "beaconobservation,observations,locationprovider,beaconestimatedlocation "
         "(DELETE/UPDATE/PRAGMA/SELECT always pass)\n", g_bound, g_mode);
}
