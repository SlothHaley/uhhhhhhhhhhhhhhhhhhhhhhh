/*
 * foldertrace - observe-only taiHEN plugin for retail 3.65 SceShell.
 *
 * Purpose: find out which LiveArea database "jobs" fire (and from where) when
 * you drag an app into a full folder, so the real reject path can be located.
 *
 * It does NOT change behaviour: every hook logs, then calls the original with
 * the same arguments (4 register args + 24 stack words are forwarded, so
 * wrappers that take stack arguments or a by-value struct keep working).
 *
 * Safety:
 *  - every target's first bytes (up to the first relocated movw/movt) are compared
 *    with the 3.65 binary before hooking; any mismatch => that hook is skipped (and reported in status.txt)
 *  - if a boot marker from the previous boot is still present, the plugin
 *    assumes it crashed the shell and stays OFF (creates tripped.flag)
 *  - a file named "disable" in the data folder turns it off
 *  - memory dumps go through sceIoWrite (kernel-validated pointers)
 *
 * Output (first of ur0:data/foldertrace/, ux0:data/foldertrace/ that works):
 *   status.txt  what was hooked/skipped
 *   trace.log   one block per event
 *   trace.bin   raw memory dumps referenced from trace.log
 */

#include <stdint.h>
#include <stddef.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <taihen.h>

#define SHELL_NAME        "SceShell"
#define NSTK              24            /* stack words forwarded to the original */
#define DUMP_ARG_LEN      192
#define DUMP_PAGE_LEN     384
#define DUMP_MODEL_LEN    256
#define MODEL_GLOBAL_OFF  0x12154       /* seg1 offset of the home-screen model pointer (3.65) */
#define STACK_SCAN_BYTES  1024
#define GAP_US            2000000ULL
#define LOG_CAP           (16u * 1024u * 1024u)
#define BIN_CAP           (32u * 1024u * 1024u)
#define GUARD_SECONDS     90


/* -nostdlib build: no libc, so tiny local helpers (no libc calls, no newlib state) */
static uint32_t ft_strlen(const char *s) { uint32_t n = 0; while (s[n]) n++; return n; }
static void ft_strcpy(char *d, const char *s) { while ((*d++ = *s++)) {} }
static void ft_strcat(char *d, const char *s) { d += ft_strlen(d); ft_strcpy(d, s); }
static int ft_memcmp(const void *a, const void *b, uint32_t n) {
  const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
  for (uint32_t i = 0; i < n; i++) if (x[i] != y[i]) return (int)x[i] - (int)y[i];
  return 0;
}
static void ft_memset(void *p, int v, uint32_t n) { volatile uint8_t *q = (volatile uint8_t *)p; while (n--) *q++ = (uint8_t)v; }

typedef struct {
  const char *name;
  uint32_t off;          /* function start, offset into segment 0 (Thumb) */
  uint8_t snap;          /* also snapshot the home-screen model on entry */
  uint8_t n;             /* bytes of exp[] to compare (stops before relocated movw/movt) */
  uint8_t exp[10];       /* expected first bytes (from the 3.65 binary) */
} hook_def_t;

static const hook_def_t H[] = {
  {"GetPageLayout", 0x1c4e4c, 0, 10, {0x2d,0xe9,0xf0,0x4f,0x83,0xb0,0x02,0x91,0xdd,0xf8}},
  {"GetPageTheme", 0x1c5172, 0, 10, {0x2d,0xe9,0xf0,0x4f,0x83,0xb0,0x02,0x91,0xdd,0xf8}},
  {"CreateNewPage", 0x1c5848, 1, 10, {0x2d,0xe9,0xf0,0x4f,0x85,0xb0,0x03,0x91,0xdd,0xf8}},
  {"DeletePage", 0xa8abe, 1, 8, {0x2d,0xe9,0xf0,0x41,0x86,0xb0,0x0f,0x1c,0x47,0xf6}},
  {"GetAppInfo", 0x1c5ba6, 0, 10, {0x2d,0xe9,0xf0,0x4f,0x81,0xb0,0x0a,0x9d,0x00,0x26}},
  {"GetIconInfo", 0x1c5d92, 0, 10, {0x2d,0xe9,0xf0,0x4f,0x81,0xb0,0x0a,0x9d,0x00,0x26}},
  {"SetIconInfo", 0x1c5f38, 1, 10, {0x2d,0xe9,0xf0,0x4f,0x85,0xb0,0x03,0x91,0xdd,0xf8}},
  {"SetPageTheme", 0xd274c, 0, 6, {0x2d,0xe9,0xf0,0x47,0x90,0xb0,0x47,0xf6,0x14,0x2a}},
  {"InsertAppInfo", 0x1c6110, 1, 10, {0x2d,0xe9,0xf0,0x4f,0x87,0xb0,0x06,0x91,0x10,0x99}},
  {"UpdateAppInfo", 0x1c6340, 1, 10, {0x2d,0xe9,0xf0,0x4f,0x85,0xb0,0x03,0x91,0xdd,0xf8}},
  {"UpdateAppInfoDiff", 0x1c6568, 1, 10, {0x2d,0xe9,0xf0,0x4f,0x87,0xb0,0x06,0x91,0x10,0x99}},
  {"CreateNewPageAndInsertApp", 0x1c67e2, 1, 10, {0x2d,0xe9,0xf0,0x4f,0x89,0xb0,0x07,0x91,0x12,0x99}},
  {"CreateNewFolder", 0x1c6bf2, 1, 10, {0x2d,0xe9,0xf0,0x4f,0x87,0xb0,0x06,0x91,0x10,0x99}},
  {"ChangeInfo", 0x2ada04, 1, 6, {0x2d,0xe9,0xf0,0x4f,0x89,0xb0,0x47,0xf6,0x14,0x2b}},
  {"ReloadFolderIconCapture", 0xb358c, 0, 4, {0x10,0xb5,0x84,0xb0,0x47,0xf6,0x14,0x24,0xc8,0xf2}},
  {"SceAppInfoDb_a", 0x1c0164, 0, 6, {0x2d,0xe9,0xf0,0x4f,0x93,0xb0,0x47,0xf6,0x14,0x24}},
  {"SceAppInfoDb_b", 0x1c0318, 0, 6, {0x2d,0xe9,0xf0,0x4f,0x89,0xb0,0x47,0xf6,0x14,0x24}},
  {"SceAppInfoDb_c", 0x1c0434, 0, 6, {0x2d,0xe9,0xf0,0x4f,0x89,0xb0,0x47,0xf6,0x14,0x24}},
  {"SceAppInfoDb_d", 0x1c0556, 0, 6, {0x2d,0xe9,0xf0,0x4f,0x8f,0xb0,0x47,0xf6,0x14,0x24}},
  {"GetTotalPage_factory", 0x1c5a3c, 0, 10, {0x2d,0xe9,0xf0,0x4f,0x81,0xb0,0x00,0x25,0x07,0x1c}},
  {"SetPageLayout_factory", 0x1c53da, 0, 10, {0x2d,0xe9,0xf0,0x4f,0x87,0xb0,0x06,0x91,0x10,0x99}},
};
#define NH 21

static tai_hook_ref_t g_ref[NH];
static SceUID g_uid[NH];

static uint32_t text_lo, text_hi, data_lo, data_hi;
static SceUID mtx = -1;
static int log_fd = -1, bin_fd = -1;
static uint64_t last_try, last_t;
static uint32_t log_bytes, bin_off, seq;
static int cap_said;
static char base[40];

/* ------------------------------------------------------------ tiny formatter */
static char lb[8192];
static int ll;

static void pc_(char c) { if (ll < (int)sizeof(lb) - 1) lb[ll++] = c; }
static void ps(const char *s) { while (*s) pc_(*s++); }
static void px(uint32_t v) {
  static const char hx[] = "0123456789abcdef";
  ps("0x");
  for (int i = 28; i >= 0; i -= 4) pc_(hx[(v >> i) & 15]);
}
static void pd(uint64_t v) {
  char t[24]; int n = 0;
  if (!v) { pc_('0'); return; }
  while (v) { t[n++] = (char)('0' + (v % 10)); v /= 10; }
  while (n) pc_(t[--n]);
}
static void ann(uint32_t w) {
  if (w >= text_lo && w < text_hi) { ps(" T+"); px(w - text_lo); }
  else if (w >= data_lo && w < data_hi) { ps(" D+"); px(w - data_lo); }
}
static void flush_fd(int fd) {
  if (fd >= 0 && ll > 0) sceIoWrite(fd, lb, (SceSize)ll);
  ll = 0;
}
static int plausible(uint32_t w) { return w >= 0x81000000u && w < 0xA0000000u && !(w & 3); }

/* ------------------------------------------------------------------- files */
static int exists(const char *name) {
  char p[96];
  ft_strcpy(p, base); ft_strcat(p, "/"); ft_strcat(p, name);
  int fd = sceIoOpen(p, SCE_O_RDONLY, 0);
  if (fd < 0) return 0;
  sceIoClose(fd);
  return 1;
}
static int open_in(const char *name, int flags) {
  char p[96];
  ft_strcpy(p, base); ft_strcat(p, "/"); ft_strcat(p, name);
  return sceIoOpen(p, flags, 0777);
}
static void touch(const char *name) { int fd = open_in(name, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC); if (fd >= 0) sceIoClose(fd); }
static void rm(const char *name) { char p[96]; ft_strcpy(p, base); ft_strcat(p, "/"); ft_strcat(p, name); sceIoRemove(p); }

static int pick_base(void) {
  static const char *c[2] = { "ur0:data/foldertrace", "ux0:data/foldertrace" };
  for (int i = 0; i < 2; i++) {
    sceIoMkdir(c[i], 0777);              /* ok if it already exists */
    ft_strcpy(base, c[i]);
    int fd = open_in("probe.tmp", SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC);
    if (fd >= 0) { sceIoClose(fd); rm("probe.tmp"); return 1; }
  }
  base[0] = 0;
  return 0;
}

static int lock(void) { return mtx >= 0 && sceKernelLockMutex(mtx, 1, NULL) >= 0; }
static void unlock(void) { sceKernelUnlockMutex(mtx, 1); }

static int ensure_open(void) {
  if (log_fd >= 0) return 1;
  if (!base[0]) return 0;
  uint64_t now = (uint64_t)sceKernelGetSystemTimeWide();
  if (last_try && now - last_try < 1000000ULL) return 0;
  last_try = now;
  log_fd = open_in("trace.log", SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC);
  bin_fd = open_in("trace.bin", SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC);
  if (log_fd < 0) return 0;
  ps("foldertrace session start\ntext "); px(text_lo); ps(" size "); px(text_hi - text_lo);
  ps("\ndata "); px(data_lo); ps(" size "); px(data_hi - data_lo);
  ps("\noffsets below are T+ (text) / D+ (data) relative to those bases\n\n");
  flush_fd(log_fd);
  return 1;
}

/* write a memory range to trace.bin; sceIoWrite validates the pointer */
static void dump_ptr(const char *tag, uint32_t idx, uint32_t addr, uint32_t len) {
  if (bin_fd < 0 || !plausible(addr) || bin_off + len > BIN_CAP) return;
  int n = sceIoWrite(bin_fd, (const void *)(uintptr_t)addr, len);
  ps("  DUMP "); ps(tag); ps("["); pd(idx); ps("] addr="); px(addr);
  if (n == (int)len) { ps(" bin=@"); px(bin_off); ps(" len="); pd(len); bin_off += len; }
  else if (n > 0)    { ps(" bin=@"); px(bin_off); ps(" len="); pd((uint32_t)n); ps(" (partial)"); bin_off += (uint32_t)n; }
  else               { ps(" UNREADABLE"); }
  ps("\n");
}

static void snapshot(void) {
  if (!data_lo) return;
  uint32_t mp = *(volatile uint32_t *)(uintptr_t)(data_lo + MODEL_GLOBAL_OFF);
  ps("  model="); px(mp);
  if (!plausible(mp)) { ps("\n"); return; }
  uint32_t arr = *(volatile uint32_t *)(uintptr_t)(mp + 44);
  uint32_t cnt = *(volatile uint32_t *)(uintptr_t)(mp + 48);
  ps(" vec="); px(arr); ps(" count="); pd(cnt); ps("\n");
  dump_ptr("model", 0, mp, DUMP_MODEL_LEN);
  if (plausible(arr) && cnt > 0 && cnt <= 64) {
    dump_ptr("pagevec", 0, arr, cnt * 4);
    for (uint32_t i = 0; i < cnt && i < 8; i++) {
      uint32_t e = *(volatile uint32_t *)(uintptr_t)(arr + 4 * i);
      if (e) dump_ptr("page", i, e - 104, DUMP_PAGE_LEN);   /* element = page object + 104 */
    }
  }
}

/* ------------------------------------------------------------------ tracing */
static void trace_enter(uint32_t id, uint32_t lr, const uint32_t *args) {
  if (!lock()) return;
  if (!ensure_open()) { unlock(); return; }
  if (log_bytes > LOG_CAP || bin_off > BIN_CAP) {
    if (!cap_said) { cap_said = 1; ps("=== size cap reached, logging stopped ===\n"); flush_fd(log_fd); }
    unlock(); return;
  }
  uint64_t t = (uint64_t)sceKernelGetSystemTimeWide();
  if (last_t && t - last_t > GAP_US) { ps("\n=== GAP "); pd((t - last_t) / 1000); ps(" ms ===\n\n"); }
  last_t = t;

  SceKernelThreadInfo ti;
  ft_memset(&ti, 0, sizeof(ti));
  ti.size = sizeof(ti);
  int have_ti = sceKernelGetThreadInfo(sceKernelGetThreadId(), &ti) >= 0;

  ps("#"); pd(++seq); ps(" t="); pd(t / 1000); ps("ms ENTER "); ps(H[id].name);
  ps(" lr="); px(lr & ~1u); ann(lr & ~1u);
  if (have_ti) { ps(" thr="); ps(ti.name); }
  ps("\n  args:");
  for (int i = 0; i < 12; i++) { ps(" "); px(args[i]); ann(args[i]); }
  ps("\n");

  if (have_ti && ti.stack) {                       /* poor man's backtrace */
    uint32_t lo = (uint32_t)(uintptr_t)args;
    uint32_t end = (uint32_t)(uintptr_t)ti.stack + (uint32_t)ti.stackSize;
    if (lo + STACK_SCAN_BYTES < end) end = lo + STACK_SCAN_BYTES;
    int shown = 0;
    ps("  stk:");
    for (uint32_t p = (lo + 3) & ~3u; p + 4 <= end && shown < 24; p += 4) {
      uint32_t w = *(volatile uint32_t *)(uintptr_t)p;
      if ((w & 1) && w - 1 >= text_lo && w - 1 < text_hi) { ps(" "); px(w - 1 - text_lo); shown++; }
    }
    ps("\n");
  }

  for (int i = 0; i < 6; i++) {
    uint32_t w = args[i];
    if (plausible(w)) dump_ptr("arg", (uint32_t)i, w, DUMP_ARG_LEN);
  }
  if (H[id].snap) snapshot();

  log_bytes += (uint32_t)ll;
  flush_fd(log_fd);
  unlock();
}

static void trace_exit(uint32_t id, uint32_t ret) {
  if (!lock()) return;
  if (log_fd >= 0 && log_bytes <= LOG_CAP) {
    ps("  EXIT "); ps(H[id].name); ps(" #"); pd(seq); ps(" ret="); px(ret); ps("\n");
    log_bytes += (uint32_t)ll;
    flush_fd(log_fd);
  }
  unlock();
}

/* One hook per target. Signature: 4 register args + NSTK stack words, so the
 * original sees an identical argument area. */
#define SP_DECL uint32_t s0,uint32_t s1,uint32_t s2,uint32_t s3,uint32_t s4,uint32_t s5,uint32_t s6,uint32_t s7, \
                uint32_t s8,uint32_t s9,uint32_t s10,uint32_t s11,uint32_t s12,uint32_t s13,uint32_t s14,uint32_t s15, \
                uint32_t s16,uint32_t s17,uint32_t s18,uint32_t s19,uint32_t s20,uint32_t s21,uint32_t s22,uint32_t s23
#define SP_USE  s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12,s13,s14,s15,s16,s17,s18,s19,s20,s21,s22,s23

#define MK(id) \
static uint32_t hk##id(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3, SP_DECL) { \
  uint32_t args[12] = { a0, a1, a2, a3, s0, s1, s2, s3, s4, s5, s6, s7 }; \
  trace_enter(id, (uint32_t)(uintptr_t)__builtin_return_address(0), args); \
  uint32_t r = TAI_CONTINUE(uint32_t, g_ref[id], a0, a1, a2, a3, SP_USE); \
  trace_exit(id, r); \
  return r; \
}

MK(0)
MK(1)
MK(2)
MK(3)
MK(4)
MK(5)
MK(6)
MK(7)
MK(8)
MK(9)
MK(10)
MK(11)
MK(12)
MK(13)
MK(14)
MK(15)
MK(16)
MK(17)
MK(18)
MK(19)
MK(20)

static const void *HF[NH] = { hk0,hk1,hk2,hk3,hk4,hk5,hk6,hk7,hk8,hk9,hk10,hk11,hk12,hk13,hk14,hk15,hk16,hk17,hk18,hk19,hk20 };

/* ------------------------------------------------------------ boot guard */
static int guard_thread(SceSize args, void *argp) {
  (void)args; (void)argp;
  sceKernelDelayThread((SceUInt)GUARD_SECONDS * 1000000u);
  rm("boot.marker");
  sceKernelExitDeleteThread(0);
  return 0;
}

static void status_line(int fd, const char *a, const char *b, uint32_t v, int showv) {
  ps(a); if (b) ps(b); if (showv) { ps(" "); px(v); } ps("\n");
  flush_fd(fd);
}

void _start() __attribute__((weak, alias("module_start")));

int module_start(SceSize argc, const void *args) {
  (void)argc; (void)args;
  for (int i = 0; i < NH; i++) g_uid[i] = -1;
  if (!pick_base()) return SCE_KERNEL_START_NO_RESIDENT;   /* nowhere to write */

  int st = open_in("status.txt", SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC);

  if (exists("disable")) { status_line(st, "disabled by file 'disable'", 0, 0, 0); if (st >= 0) sceIoClose(st); return SCE_KERNEL_START_NO_RESIDENT; }
  if (exists("tripped.flag")) { status_line(st, "OFF: tripped.flag present (delete it to re-enable)", 0, 0, 0); if (st >= 0) sceIoClose(st); return SCE_KERNEL_START_NO_RESIDENT; }
  if (exists("boot.marker")) {
    touch("tripped.flag");
    status_line(st, "OFF: previous boot did not finish cleanly; tripped.flag created", 0, 0, 0);
    if (st >= 0) sceIoClose(st);
    return SCE_KERNEL_START_NO_RESIDENT;
  }
  touch("boot.marker");
  SceUID gt = sceKernelCreateThread("foldertrace_guard", guard_thread, 0x10000100, 0x1000, 0, 0, NULL);
  if (gt >= 0) sceKernelStartThread(gt, 0, NULL);

  tai_module_info_t ti;
  ft_memset(&ti, 0, sizeof(ti));
  ti.size = sizeof(ti);
  if (taiGetModuleInfo(SHELL_NAME, &ti) < 0) {
    status_line(st, "FAIL: taiGetModuleInfo(SceShell)", 0, 0, 0);
    if (st >= 0) sceIoClose(st);
    rm("boot.marker");
    return SCE_KERNEL_START_NO_RESIDENT;
  }
  SceKernelModuleInfo mi;
  ft_memset(&mi, 0, sizeof(mi));
  mi.size = sizeof(mi);
  if (sceKernelGetModuleInfo(ti.modid, &mi) < 0) {
    status_line(st, "FAIL: sceKernelGetModuleInfo", 0, 0, 0);
    if (st >= 0) sceIoClose(st);
    rm("boot.marker");
    return SCE_KERNEL_START_NO_RESIDENT;
  }
  text_lo = (uint32_t)(uintptr_t)mi.segments[0].vaddr;
  text_hi = text_lo + (uint32_t)mi.segments[0].memsz;
  data_lo = (uint32_t)(uintptr_t)mi.segments[1].vaddr;
  data_hi = data_lo + (uint32_t)mi.segments[1].memsz;

  status_line(st, "module NID", 0, ti.module_nid, 1);
  status_line(st, "text base", 0, text_lo, 1);
  status_line(st, "text size", 0, text_hi - text_lo, 1);
  status_line(st, "data base", 0, data_lo, 1);
  status_line(st, "data size", 0, data_hi - data_lo, 1);

  mtx = sceKernelCreateMutex("foldertrace_mtx", SCE_KERNEL_MUTEX_ATTR_RECURSIVE, 0, NULL);

  int ok = 0;
  for (int i = 0; i < NH; i++) {
    g_uid[i] = -1;
    const uint8_t *fn = (const uint8_t *)(uintptr_t)(text_lo + H[i].off);
    if (H[i].off + 10 > text_hi - text_lo || ft_memcmp(fn, H[i].exp, H[i].n) != 0) {
      status_line(st, "SKIP (prologue mismatch): ", H[i].name, H[i].off, 1);
      continue;
    }
    g_uid[i] = taiHookFunctionOffset(&g_ref[i], ti.modid, 0, H[i].off, 1, HF[i]);
    if (g_uid[i] >= 0) { ok++; status_line(st, "hooked: ", H[i].name, H[i].off, 1); }
    else status_line(st, "FAIL hook: ", H[i].name, (uint32_t)g_uid[i], 1);
  }
  ps("hooks installed: "); pd((uint64_t)ok); ps("\n"); flush_fd(st);
  if (st >= 0) sceIoClose(st);
  return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args) {
  (void)argc; (void)args;
  for (int i = 0; i < NH; i++)
    if (g_uid[i] >= 0) taiHookRelease(g_uid[i], g_ref[i]);
  return SCE_KERNEL_STOP_SUCCESS;
}
