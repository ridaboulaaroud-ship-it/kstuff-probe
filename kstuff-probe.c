/* kstuff-probe.c — payload autonome PS5 : dump noyau + scan de candidats
 * 100% lecture seule cote noyau. Ecrit uniquement sur la cle USB.
 * Se termine proprement (pas de boucle infinie) pour un arret propre.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define VER      "probe-1.4"
#define LOG_NAME "kstuff_probe.txt"

/* Tailles de dump si l'exploit ne les fournit pas.
   Baisse-les (ex. 0x1000000 / 0x2000000) pour ecrire moins de donnees. */
#define DUMP_TEXT_DEF 0x2000000   /* 32 Mo */
#define DUMP_DATA_DEF 0x4000000   /* 64 Mo */

/* ---------------- memoire (pas de libc) ---------------- */
void *memcpy(void *d, const void *s, size_t n);
void *memset(void *d, int c, size_t n);
int   memcmp(const void *a, const void *b, size_t n);

__attribute__((no_builtin("memcpy")))
void *memcpy(void *d, const void *s, size_t n) {
    uint8_t *dd = (uint8_t *)d; const uint8_t *ss = (const uint8_t *)s;
    while (n--) *dd++ = *ss++;
    return d;
}
__attribute__((no_builtin("memset")))
void *memset(void *d, int c, size_t n) {
    uint8_t *dd = (uint8_t *)d;
    while (n--) *dd++ = (uint8_t)c;
    return d;
}
int memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
    while (n--) { if (*x != *y) return (int)*x - (int)*y; x++; y++; }
    return 0;
}

/* ---------------- syscalls ---------------- */
static long ksys(long n, long a, long b, long c, long d, long e, long f) {
    register long r10 __asm__("r10") = d;
    register long r8  __asm__("r8")  = e;
    register long r9  __asm__("r9")  = f;
    long ret;
    __asm__ volatile("syscall" : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
}
#define SYS_exit  1
#define SYS_write 4
#define SYS_open  5
#define SYS_close 6
#define SYS_nanosleep 240
#define SYS_jailbreak 599
#define O_WRONLY 0x1
#define O_APPEND 0x8
#define O_CREAT  0x200
#define O_TRUNC  0x400

/* ---------------- sortie ---------------- */
static long g_log = -1;
static char g_logp[128];

static void out(const char *s) {
    size_t k = 0; while (s[k]) k++;
    ksys(SYS_write, 1, (long)s, k, 0, 0, 0);
    if (g_log >= 0) ksys(SYS_write, g_log, (long)s, k, 0, 0, 0);
}

/* ferme puis rouvre : garantit que tout est ecrit sur la cle avant la suite */
static void log_open(int trunc) {
    if (g_log >= 0) { ksys(SYS_close, g_log, 0, 0, 0, 0, 0); g_log = -1; }
    g_log = ksys(SYS_open, (long)g_logp, O_WRONLY|O_CREAT|(trunc ? O_TRUNC : O_APPEND),
                 0644, 0, 0, 0);
}
#define log_flush() log_open(0)

static void outx(uint64_t v) {
    char b[24]; int i = 24; b[--i] = 0;
    if (!v) b[--i] = '0';
    while (v && i) { b[--i] = "0123456789abcdef"[v & 15]; v >>= 4; }
    out(&b[i]);
}

static void outd(int64_t v) {
    if (v < 0) { out("-"); v = -v; }
    outx((uint64_t)v);
}

static void kprintf(const char *f, ...) {
    __builtin_va_list ap; __builtin_va_start(ap, f);
    for (; *f; f++) {
        if (*f != '%') { char c[2] = { *f, 0 }; out(c); continue; }
        f++;
        while (*f == '#' || *f == '-' || *f == '+' || *f == ' ' || *f == '0' ||
               (*f >= '1' && *f <= '9') || *f == 'l' || *f == 'h' || *f == 'z')
            f++;
        switch (*f) {
            case 's': out(__builtin_va_arg(ap, const char *)); break;
            case 'd': case 'i': outd(__builtin_va_arg(ap, int)); break;
            case 'u': outx((uint64_t)__builtin_va_arg(ap, unsigned)); break;
            case 'x': outx(__builtin_va_arg(ap, uint64_t)); break;
            case 'p': out("0x"); outx(__builtin_va_arg(ap, uint64_t)); break;
            case '%': out("%"); break;
            case 0: __builtin_va_end(ap); return;
        }
    }
    __builtin_va_end(ap);
}

/* ---------------- etat noyau ---------------- */
struct kstuff_api {
    uint64_t kern_base, data_base, text_size, data_size;
    int (*kread)(uint64_t, void *, size_t);
    int (*kwrite)(uint64_t, const void *, size_t);
    int (*kcall)(uint64_t, uint64_t *, int, uint64_t *);
};

static struct {
    uint64_t kern_base, data_base, text_size, data_size;
    int (*kread)(uint64_t, void *, size_t);
} K;

static int kread(void *dst, uint64_t addr, size_t n) {
    if (K.kread) return K.kread(addr, dst, n);
    return -1;
}

/* ---------------- utilitaires ---------------- */
static uint64_t rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }

static int kmemmem(const uint8_t *h, size_t hn, const char *s) {
    size_t sl = 0; while (s[sl]) sl++;
    if (!sl || sl > hn) return 0;
    for (size_t i = 0; i + sl <= hn; i++)
        if (memcmp(h + i, s, sl) == 0) return 1;
    return 0;
}

static void join_path(char *dst, const char *dir, const char *name) {
    int i = 0;
    while (dir[i]) { dst[i] = dir[i]; i++; }
    for (int j = 0; name[j]; j++) dst[i++] = name[j];
    dst[i] = 0;
}

static uint64_t idt_get(void) {
    struct { uint16_t l; uint64_t b; } __attribute__((packed)) r;
    __asm__ volatile("sidt %0" : "=m"(r));
    return r.b;
}

static uint64_t cr3_get(void) {
    uint64_t v; __asm__ volatile("mov %%cr3,%0" : "=r"(v)); return v;
}

/* ---------------- scanner ---------------- */
static uint8_t g_buf[0x10000 + 0x40];

static uint64_t kscan(const uint8_t *pat, const char *pmask,
                      size_t len, uint64_t start, uint64_t end)
{
    for (uint64_t base = start; base + len <= end; base += 0x10000) {
        size_t n = sizeof g_buf;
        if (base + n > end) n = end - base;
        if (n < len) break;
        if (kread(g_buf, base, n) != 0) continue;
        for (size_t i = 0; i + len <= n; i++) {
            bool ok = true;
            for (size_t j = 0; j < len; j++)
                if (pmask[j] != '?' && g_buf[i + j] != pat[j]) { ok = false; break; }
            if (ok) return base + i;
        }
    }
    return 0;
}

static uint64_t kscan_str(const char *s, uint64_t start, uint64_t end) {
    size_t sl = 0; while (s[sl]) sl++;
    static char pmask[256];
    for (size_t i = 0; i < sl; i++) pmask[i] = 'x';
    pmask[sl] = 0;
    return kscan((const uint8_t *)s, pmask, sl, start, end);
}

static uint64_t func_start(uint64_t addr) {
    uint64_t page = addr & ~0xfffULL;
    for (int k = 0; k < 12 && page >= K.kern_base; k++, page -= 0x1000) {
        if (kread(g_buf, page, 0x1000) != 0) continue;
        for (int i = 0x1000 - 4; i >= 0; i--) {
            if (g_buf[i]==0xF3 && g_buf[i+1]==0x0F && g_buf[i+2]==0x1E && g_buf[i+3]==0xFA)
                return page + i;
            if (g_buf[i]==0x55 && g_buf[i+1]==0x48 && g_buf[i+2]==0x89 && g_buf[i+3]==0xE5)
                return page + i;
        }
    }
    return 0;
}

/* ---------------- dump ELF ---------------- */
struct __attribute__((packed)) ehdr {
    uint8_t ident[16]; uint16_t type, machine; uint32_t version;
    uint64_t entry, phoff, shoff; uint32_t flags;
    uint16_t ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
};

struct __attribute__((packed)) phdr {
    uint32_t type, flags;
    uint64_t offset, vaddr, paddr, filesz, memsz, align;
};

static const char *g_dir = "/mnt/usb0/";

static void mkelf(const char *name, uint64_t vaddr, uint64_t size) {
    char path[128];
    join_path(path, g_dir, name);

    long fd = ksys(SYS_open, (long)path, O_WRONLY|O_CREAT|O_TRUNC, 0644, 0, 0, 0);
    if (fd < 0) { kprintf("dump KO: %s\n", path); return; }

    struct ehdr e; memset(&e, 0, sizeof e);
    e.ident[0]=0x7f; e.ident[1]='E'; e.ident[2]='L'; e.ident[3]='F';
    e.ident[4]=2; e.ident[5]=1; e.ident[6]=1;
    e.type=2; e.machine=62; e.version=1;
    e.phoff=sizeof e; e.ehsize=sizeof e;
    e.phentsize=sizeof(struct phdr); e.phnum=1;

    struct phdr p; memset(&p, 0, sizeof p);
    p.type=1; p.flags=5;
    p.offset=0x1000; p.vaddr=vaddr; p.paddr=vaddr;
    p.filesz=size; p.memsz=size; p.align=0x1000;

    ksys(SYS_write, fd, (long)&e, sizeof e, 0, 0, 0);
    ksys(SYS_write, fd, (long)&p, sizeof p, 0, 0, 0);
    static uint8_t pad[0x1000];
    ksys(SYS_write, fd, (long)pad, 0x1000 - (sizeof e + sizeof p), 0, 0, 0);

    for (uint64_t off = 0; off < size; off += 0x10000) {
        size_t n2 = 0x10000;
        if (off + n2 > size) n2 = size - off;
        kread(g_buf, vaddr + off, n2);
        ksys(SYS_write, fd, (long)g_buf, n2, 0, 0, 0);
    }
    ksys(SYS_close, fd, 0, 0, 0, 0, 0);
    kprintf("dump OK : %s  (%#lx octets @ %p)\n", path, size, vaddr);
}

/* ---------------- ancres ---------------- */
static const uint8_t AES_SBOX[16] = {
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,
    0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76 };

static const uint8_t SHA256_IV[16] = {
    0x67,0xE6,0x09,0x6A,0x85,0xAE,0x67,0xBB,
    0x72,0xF3,0x6E,0x3C,0x3A,0xF5,0x4F,0xA5 };

static const char M16[] = "xxxxxxxxxxxxxxxx";

static void probe_crypto(void) {
    uint64_t a, f;
    out("\n--- ancres crypto ---\n");

    a = kscan(AES_SBOX, M16, 16, K.kern_base, K.kern_base + K.text_size);
    if (a) {
        kprintf("aes_sbox        %p  off %#lx\n", a, a - K.kern_base);
        f = func_start(a);
        if (f) kprintf("  -> fonction    %p  off %#lx\n", f, f - K.kern_base);
    } else out("aes_sbox        : introuvable\n");

    a = kscan(SHA256_IV, M16, 16, K.kern_base, K.kern_base + K.text_size);
    if (a) {
        kprintf("sha256_iv       %p  off %#lx\n", a, a - K.kern_base);
        f = func_start(a);
        if (f) kprintf("  -> fonction    %p  off %#lx\n", f, f - K.kern_base);
    } else out("sha256_iv       : introuvable\n");
}

static void probe_strings(void) {
    static const char *need[] = {
        "sceSblAuthMgrVerifyHeader", "SceSblAuthMgr", "sceSblAuthMgrIsLoadable",
        "SceSblPfs", "sceSblPfsCrypt", "a53", "SceA53", "Ppr", "Kraken"
    };
    out("\n--- chaines dans .data ---\n");
    for (size_t i = 0; i < sizeof need / sizeof *need; i++) {
        uint64_t a = kscan_str(need[i], K.data_base, K.data_base + K.data_size);
        if (a) kprintf("%s  %p  off %#lx\n", need[i], a, a - K.data_base);
        else   kprintf("%s  (absent)\n", need[i]);
    }
}

static void probe_allproc(void) {
    uint64_t end = K.data_base + 0x800000;
    out("\n--- candidats allproc ---\n");
    int found = 0, probes = 0;
    for (uint64_t off = 0; off + 0x10000 <= end - K.data_base; off += 0x10000) {
        if (kread(g_buf, K.data_base + off, 0x10000) != 0) continue;
        for (size_t i = 0; i + 8 <= 0x10000; i += 8) {
            uint64_t p = rd64(g_buf + i);
            if (p < K.data_base || p > K.data_base + 0x4000000) continue;
            if (p & 0xf) continue;
            if (++probes > 30000) { out("(limite de sondage atteinte)\n"); return; }
            static uint8_t pr[0x300];
            if (kread(pr, p, sizeof pr) != 0) continue;
            if (kmemmem(pr, sizeof pr, "kernel") || kmemmem(pr, sizeof pr, "init")) {
                kprintf("candidat : liste @ %p  -> proc %p  (off %#lx)\n",
                        K.data_base + off + i, p, (K.data_base + off + i) - K.data_base);
                if (++found >= 10) return;
            }
        }
    }
    if (!found) out("aucun candidat trouve\n");
}

/* ---------------- entree ---------------- */
void _start(void) {
    out("\n================================\n");
    out("  kstuff probe " VER "  (lecture seule)\n");
    out("================================\n\n");

    g_dir = "/mnt/usb0/";
    long t = ksys(SYS_open, (long)"/mnt/usb0/.probe", O_WRONLY|O_CREAT, 0644, 0, 0, 0);
    if (t >= 0) ksys(SYS_close, t, 0, 0, 0, 0, 0);
    else g_dir = "/data/";

    join_path(g_logp, g_dir, LOG_NAME);
    log_open(1);
    kprintf("sortie : %s\n", g_dir);

    struct kstuff_api *api = (struct kstuff_api *)ksys(SYS_jailbreak, 0, 0, 0, 0, 0, 0);
    kprintf("jailbreak() -> %p\n", (uint64_t)api);
    if (!api || !api->kread) {
        out("!! pas de R/W noyau : lance l'exploit AVANT ce payload\n");
        log_flush();
        goto fin;
    }

    K.kern_base = api->kern_base;
    K.data_base = api->data_base;
    K.text_size = api->text_size;
    K.data_size = api->data_size;
    K.kread     = api->kread;

    if (K.text_size < 0x100000 || K.text_size > 0x8000000) K.text_size = DUMP_TEXT_DEF;
    if (K.data_size < 0x100000 || K.data_size > 0x8000000) K.data_size = DUMP_DATA_DEF;

    out("\n--- bases ---\n");
    kprintf("kern_base       %p\n", K.kern_base);
    kprintf("data_base       %p\n", K.data_base);
    kprintf("text_size       %#lx\n", K.text_size);
    kprintf("data_size       %#lx\n", K.data_size);
    kprintf("idt (sidt)      %p\n", idt_get());
    kprintf("cr3 (pml4)      %p\n", cr3_get());

    if ((K.kern_base >> 32) != 0xffffffffULL)
        out("!! kern_base ne ressemble pas a une adresse noyau\n");
    if (K.data_base < K.kern_base)
        out("!! data_base < kern_base : structure inattendue\n");

    {
        uint8_t test[16];
        if (kread(test, K.kern_base, 16) == 0) {
            out("test lecture kern_base : ");
            for (int i = 0; i < 16; i++) { outx(test[i]); out(" "); }
            out("\n");
        } else out("test lecture kern_base : ECHEC\n");
    }

    log_flush();

    out("\n--- dump noyau ---\n");
    mkelf("kernel_text.elf", K.kern_base, K.text_size);
    log_flush();
    mkelf("kernel_data.elf", K.data_base, K.data_size);
    log_flush();

    probe_crypto();
    log_flush();
    probe_strings();
    log_flush();
    probe_allproc();

    out("\n--- fin ---\n");
    out("Envoie-moi kstuff_probe.txt\n");
    log_flush();

fin:
    /* petite pause puis on rend la main : la console redevient normale,
       ce qui permet un arret PROPRE par le menu (protection du SSD). */
    {
        static long ts[2] = { 3, 0 };
        ksys(SYS_nanosleep, (long)ts, 0, 0, 0, 0, 0);
    }
    ksys(SYS_exit, 0, 0, 0, 0, 0, 0);
    for (;;) {
        static long ts[2] = { 1, 0 };
        ksys(SYS_nanosleep, (long)ts, 0, 0, 0, 0, 0);
    }
}
