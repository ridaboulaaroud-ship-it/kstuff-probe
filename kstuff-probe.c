/*
 * kstuff-probe.c -- v3.9
 *
 * PHASE 1 (defaut) : args, firmware, bases, lectures brutes, parcours allproc.
 *                    Les points [8] a [12] ne sont PAS compiles.
 * PHASE 2          : + scan des ancres + test isole du syscall 599.
 * PHASE 3          : + dump brut.
 *
 * Statuts : 1 = OK, 0 = KO, 2 = TRONQUE, -1 = non evalue.
 *
 * Faits verifies dans le source du SDK (ps5-payload-dev/sdk) :
 *   - kernel_copyout() : 0 = succes, -1 = echec. Aucun compte d'octets.
 *     Pipe arme avec cnt = in = 0x40000000 : SYS_read(n) rend n octets.
 *   - KERNEL_ADDRESS_ALLPROC contient un pointeur direct vers le premier
 *     struct proc ; lien de liste a l'offset 0 ; p_pid a 0xBC ; la liste se
 *     termine sur un lien NUL (c'est ce que fait kernel_get_proc()).
 *   - kernel_get_fw_version() : SYS_dynlib_get_obj_member(0x2, 8), sans pipe.
 *
 * LIMITES ASSUMEES :
 *   - fw_table[] recopie la table du SDK : detecteur d'incoherence, pas
 *     validation independante.
 *   - [7] est un RECOUPEMENT : kernel_get_proc() et notre parcours tournent
 *     dans le meme environnement noyau. Ce n'est pas une preuve independante.
 *   - [4c] effectue une VRAIE lecture noyau et peut parfaitement reussir.
 *     Ce qui est "hors verdict" n'est pas la lecture, c'est son ROLE.
 *   - La validation operationnelle RETENUE POUR LE VERDICT repose donc
 *     uniquement sur [4a] et [4b].
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include <ps5/kernel.h>
#include <ps5/klog.h>
#include <ps5/payload.h>

#define PROBE_VERSION   "3.9"
#define LOG_NAME        "kstuff_probe.txt"

#define PHASE           1

#define KREAD_CHUNK     4096u
#define SCAN_CHUNK      8192u
#define SCAN_TEXT_SIZE  (32u * 1024u * 1024u)
#define SCAN_DATA_SIZE  ( 8u * 1024u * 1024u)
#define WALK_MAX        256

/* etats de test */
#define ST_OK      1
#define ST_KO      0
#define ST_TRUNC   2
#define ST_NA     -1

/* niveaux de verdict */
#define V_FULL        3
#define V_PARTIAL     2
#define V_NO_PID      1
#define V_INCOMPLETE  0

/* codes de sortie -- convention explicite, ecrite aussi dans le journal */
#define RC_FULL        0
#define RC_PARTIAL     2
#define RC_NO_PID      3
#define RC_INCOMPLETE  1

static int  g_fd  = -1;
static char g_dir[64] = "/data";

static const char *st2s(int s) {
  switch (s) {
  case ST_OK:    return "OK";
  case ST_KO:    return "KO";
  case ST_TRUNC: return "TRONQUE";
  case ST_NA:    return "non evalue";
  default:       return "?";
  }
}


/* ------------------------------------------------------------------ */
/* sortie                                                             */
/* ------------------------------------------------------------------ */

static int write_all(int fd, const void *b, size_t n) {
  const uint8_t *p = (const uint8_t *)b;
  while (n) {
    ssize_t r = write(fd, p, n);
    if (r <= 0) return -1;
    p += r;
    n -= (size_t)r;
  }
  return 0;
}

static void logf(const char *fmt, ...) {
  char buf[768];
  size_t l;
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  if (g_fd >= 0) write_all(g_fd, buf, strlen(buf));
  fputs(buf, stdout);

  l = strlen(buf);
  if (l && buf[l - 1] == '\n') buf[l - 1] = 0;
  if (buf[0]) klog_puts(buf);
}

static const char *open_log(void) {
  static const char *dirs[] = {
    "/mnt/usb0", "/mnt/usb1", "/mnt/usb2", "/mnt/usb3", "/data"
  };
  static char path[160];

  for (unsigned i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
    int fd;
    snprintf(path, sizeof(path), "%s/%s", dirs[i], LOG_NAME);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) {
      g_fd = fd;
      snprintf(g_dir, sizeof(g_dir), "%s", dirs[i]);
      return path;
    }
  }
  return 0;
}


/* ------------------------------------------------------------------ */
/* lecture noyau                                                      */
/* ------------------------------------------------------------------ */

static int kread(intptr_t kaddr, void *buf, size_t len) {
  uint8_t *p = (uint8_t *)buf;

  while (len) {
    size_t n = len < KREAD_CHUNK ? len : KREAD_CHUNK;
    int tries = 0;

    for (;;) {
      if (kernel_copyout(kaddr, p, n) == 0) break;
      if (++tries > 2) return -1;
    }

    p += n;
    kaddr += n;
    len -= n;
  }
  return 0;
}

static void hexdump(const char *what, intptr_t addr, const uint8_t *b, size_t n) {
  logf("    %s @ 0x%016lx\n", what, (unsigned long)(uintptr_t)addr);
  for (size_t i = 0; i < n; i += 16) {
    char line[160];
    int  p = snprintf(line, sizeof(line), "      %08lx  ",
                      (unsigned long)((uintptr_t)addr + i));
    for (size_t j = 0; j < 16 && i + j < n; j++)
      p += snprintf(line + p, sizeof(line) - (size_t)p, "%02x ", b[i + j]);
    logf("%s\n", line);
  }
}


/* ------------------------------------------------------------------ */
/* phase 2 : ancres                                                   */
/* ------------------------------------------------------------------ */

#if PHASE >= 2
typedef struct {
  const char    *name;
  const uint8_t *pat;
  size_t         len;
  intptr_t       hit;
  intptr_t       region_base;
  const char    *region;
  int            found;
} anchor_t;

static const uint8_t pat_aes_sbox[16] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
  0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76
};

static const uint8_t pat_aes_inv[16] = {
  0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,
  0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb
};

static const uint8_t pat_sha_iv_le[32] = {
  0x67,0xe6,0x09,0x6a, 0x85,0xae,0x67,0xbb,
  0x72,0xf3,0x6e,0x3c, 0x3a,0xf5,0x4f,0xa5,
  0x7f,0x52,0x0e,0x51, 0x8c,0x68,0x05,0x9b,
  0xab,0xd9,0x83,0x1f, 0x19,0xcd,0xe0,0x5b
};

static const uint8_t pat_sha_iv_be[32] = {
  0x6a,0x09,0xe6,0x67, 0xbb,0x67,0xae,0x85,
  0x3c,0x6e,0xf3,0x72, 0xa5,0x4f,0xf5,0x3a,
  0x51,0x0e,0x52,0x7f, 0x9b,0x05,0x68,0x8c,
  0x1f,0x83,0xd9,0xab, 0x5b,0xe0,0xcd,0x19
};

static int scan_region(const char *rname, intptr_t base, size_t size,
                       anchor_t *an, int nan) {
  size_t   overlap = 0;
  uint8_t *buf;
  size_t   step = SCAN_CHUNK;
  int      complete = 1;

  for (int i = 0; i < nan; i++)
    if (an[i].len > overlap) overlap = an[i].len;

  if (!(buf = (uint8_t *)malloc(step + 64))) {
    logf("    [!] malloc echoue pour le scan\n");
    return 0;
  }

  for (size_t off = 0; off < size; off += step) {
    size_t want = size - off;
    if (want > step + overlap - 1) want = step + overlap - 1;

    if (kread(base + (intptr_t)off, buf, want)) {
      logf("    [!] lecture %s +0x%lx echouee, scan interrompu\n",
           rname, (unsigned long)off);
      complete = 0;
      break;
    }

    for (size_t i = 0; i < want; i++) {
      for (int a = 0; a < nan; a++) {
        if (an[a].found) continue;
        if (an[a].len > want - i) continue;
        if (buf[i] != an[a].pat[0]) continue;
        if (!memcmp(buf + i, an[a].pat, an[a].len)) {
          an[a].found       = 1;
          an[a].hit         = base + (intptr_t)off + (intptr_t)i;
          an[a].region_base = base;
          an[a].region      = rname;
        }
      }
    }
    if (off + step >= size) break;
  }

  free(buf);
  return complete;
}
#endif


/* ------------------------------------------------------------------ */
/* phase 3 : dump                                                     */
/* ------------------------------------------------------------------ */

#if PHASE >= 3
static int dump_region(const char *fname, intptr_t base, size_t size) {
  char     path[160];
  uint8_t *buf;
  int      fd;
  size_t   off;

  if (!(buf = (uint8_t *)malloc(KREAD_CHUNK))) {
    logf("    [!] dump: malloc echoue\n");
    return 0;
  }

  snprintf(path, sizeof(path), "%s/%s", g_dir, fname);
  if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666)) < 0) {
    logf("    [!] dump: impossible d'ouvrir %s\n", path);
    free(buf);
    return 0;
  }

  for (off = 0; off < size; off += KREAD_CHUNK) {
    size_t n = (size - off) < KREAD_CHUNK ? (size - off) : KREAD_CHUNK;
    if (kread(base + (intptr_t)off, buf, n)) {
      logf("    [!] dump: lecture echouee a +0x%lx\n", (unsigned long)off);
      break;
    }
    if (write_all(fd, buf, n)) {
      logf("    [!] dump: ecriture echouee a +0x%lx\n", (unsigned long)off);
      break;
    }
  }

  fsync(fd);
  close(fd);
  free(buf);
  logf("    dump %s : 0x%lx octets ecrits\n", path, (unsigned long)off);
  return off >= size;
}
#endif


/* ------------------------------------------------------------------ */
/* table locale -- recopie de la table du SDK (13.00 -> 13.60)        */
/* ------------------------------------------------------------------ */

static const struct {
  uint32_t fw;
  uint32_t delta;        /* DATA_BASE - TEXT_BASE */
  uint32_t allproc_off;  /* ALLPROC   - DATA_BASE */
} fw_table[] = {
  { 0x13000000u, 0x0cb0000u, 0x28c5e00u },
  { 0x13200000u, 0x0cb0000u, 0x28c5e00u },
  { 0x13400000u, 0x0cb0000u, 0x28c9e80u },
  { 0x13600000u, 0x0cc0000u, 0x28c9e80u },
};


/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
#if PHASE >= 2
  anchor_t        anchors[4];
  int             anchors_found = -1;
#endif
  payload_args_t *pa;
  const char     *logpath;
  uint32_t        fw;
  uintptr_t       text = 0, data = 0, allproc = 0;
  uint8_t         probe[64];
  int             have_pipe;
  int             st_args = ST_OK, st_fw = ST_OK, st_bases = ST_OK;
  int             st_read = ST_NA, st_read_c = ST_NA;
  int             st_walk = ST_NA, st_pid = ST_NA, st_sdk = ST_NA;
  int             st_scan = ST_NA, st_dump = ST_NA;
  int             base_ok, core_ok, verdict, rc;

  (void)argc; (void)argv;

  logpath = open_log();

  logf("\n");
  logf("=====================================================\n");
  logf(" kstuff-probe v%s -- phase %d\n", PROBE_VERSION, PHASE);
  logf(" build %s %s\n", __DATE__, __TIME__);
  logf("=====================================================\n");
  logf(" log : %s\n",
       logpath ? logpath : "(aucun fichier, stdout/klog seulement)");
  logf(" pid : %d\n", (int)getpid());
#if PHASE < 2
  logf(" phase %d : les points [8] a [12] ne sont pas compiles.\n", PHASE);
  logf("            passe #define PHASE 2 pour le scan et le test 599.\n");
#endif

  /* ---- 1. prerequis ---- */
  pa = payload_get_args();
  if (!pa || !pa->rwpipe || !pa->rwpair || !pa->kpipe_addr || !pa->kdata_base_addr) {
    logf("\n[1] [KO] payload_args absents ou incomplets\n");
    st_args = ST_KO;
    have_pipe = 0;
  } else {
    logf("\n[1] payload_args recus (presence ; la preuve est en [4a][4b]) :\n");
    logf("    rwpipe     = %d / %d\n", pa->rwpipe[0], pa->rwpipe[1]);
    logf("    rwpair     = %d / %d\n", pa->rwpair[0], pa->rwpair[1]);
    logf("    kpipe_addr = 0x%016lx\n", (unsigned long)pa->kpipe_addr);
    logf("    kdata_base = 0x%016lx\n", (unsigned long)pa->kdata_base_addr);
    have_pipe = 1;
  }

  if (!have_pipe) {
    logf("    => les tests dependant du pipe seront 'non evalue'\n");
    text    = (uintptr_t)KERNEL_ADDRESS_TEXT_BASE;
    data    = (uintptr_t)KERNEL_ADDRESS_DATA_BASE;
    allproc = (uintptr_t)KERNEL_ADDRESS_ALLPROC;
  }

  /* ---- 2. firmware : sans pipe ---- */
  fw = kernel_get_fw_version();
  logf("\n[2] firmware = 0x%08x\n", (unsigned)fw);
  logf("    (via SYS_dynlib_get_obj_member, aucun usage du pipe)\n");
  if (fw == 0) { logf("    [KO] lecture libSceLibcInternal impossible\n"); st_fw = ST_KO; }

  /* ---- 3. bases ---- */
  if (!have_pipe) {
    logf("\n[3] bases : non evalue (pas de prerequis)\n");
    st_bases = ST_NA;
  } else {
    text    = (uintptr_t)KERNEL_ADDRESS_TEXT_BASE;
    data    = (uintptr_t)KERNEL_ADDRESS_DATA_BASE;
    allproc = (uintptr_t)KERNEL_ADDRESS_ALLPROC;

    logf("\n[3] bases :\n");
    logf("    TEXT_BASE   = 0x%016lx\n", (unsigned long)text);
    logf("    DATA_BASE   = 0x%016lx\n", (unsigned long)data);
    logf("    ALLPROC     = 0x%016lx\n", (unsigned long)allproc);
    logf("    SECURITY_FL = 0x%016lx\n", (unsigned long)(uintptr_t)KERNEL_ADDRESS_SECURITY_FLAGS);
    logf("    ROOTVNODE   = 0x%016lx\n", (unsigned long)(uintptr_t)KERNEL_ADDRESS_ROOTVNODE);

    if ((uintptr_t)pa->kdata_base_addr != data) {
      logf("    [KO] DATA_BASE 0x%lx != kdata_base_addr 0x%lx\n",
           (unsigned long)data, (unsigned long)pa->kdata_base_addr);
      st_bases = ST_KO;
    } else {
      logf("    [OK] DATA_BASE = kdata_base_addr du loader\n");
    }

    if (!text || !data || (text >> 48) != 0xffff || (data >> 48) != 0xffff) {
      logf("    [KO] TEXT_BASE ou DATA_BASE nul / non canonique\n");
      st_bases = ST_KO;
    } else if (!(text < data && data < allproc)) {
      logf("    [KO] ordre text < data < allproc non respecte\n");
      st_bases = ST_KO;
    } else {
      logf("    [OK] TEXT_BASE et DATA_BASE canoniques, ordre coherent\n");
    }

    if (!allproc) {
      logf("    [KO] ALLPROC nul\n"); st_bases = ST_KO;
    } else if ((allproc >> 48) != 0xffff) {
      logf("    [KO] ALLPROC 0x%016lx non canonique\n", (unsigned long)allproc);
      st_bases = ST_KO;
    } else {
      unsigned long exp_ap = 0;
      for (unsigned i = 0; i < sizeof(fw_table) / sizeof(fw_table[0]); i++)
        if ((fw & 0xffff0000u) == fw_table[i].fw) exp_ap = fw_table[i].allproc_off;
      if (!exp_ap) logf("    [!] firmware hors table locale (ALLPROC)\n");
      else if ((unsigned long)(allproc - data) == exp_ap)
        logf("    [OK] ALLPROC a l'offset attendu 0x%lx (canonique != lisible)\n", exp_ap);
      else {
        logf("    [KO] ALLPROC offset 0x%lx, attendu 0x%lx\n",
             (unsigned long)(allproc - data), exp_ap);
        st_bases = ST_KO;
      }
    }

    if (text && data && data > text) {
      unsigned long delta = (unsigned long)(data - text);
      unsigned long exp   = 0;
      logf("    delta DATA-TEXT = 0x%lx\n", delta);
      for (unsigned i = 0; i < sizeof(fw_table) / sizeof(fw_table[0]); i++)
        if ((fw & 0xffff0000u) == fw_table[i].fw) exp = fw_table[i].delta;
      if (!exp) { logf("    [KO] firmware hors table locale\n"); st_bases = ST_KO; }
      else if (exp == delta) logf("    [OK] ecart conforme (recopie SDK)\n");
      else { logf("    [KO] ecart attendu 0x%lx\n", exp); st_bases = ST_KO; }
    } else {
      st_bases = ST_KO;
    }
  }

  /* ---- 4a/4b : lectures brutes (coeur du test) ---- */
  if (!have_pipe) {
    logf("\n[4a] [4b] lectures brutes : non evalue\n");
    st_read = ST_NA;
  } else {
    st_read = ST_OK;

    memset(probe, 0xAA, sizeof(probe));
    if (kread((intptr_t)text, probe, sizeof(probe)) == 0) {
      int nz = 0;
      for (unsigned i = 0; i < sizeof(probe); i++) if (probe[i]) nz++;
      logf("\n[4a] lecture TEXT_BASE : OK -- %d/64 octets non nuls\n", nz);
      hexdump("TEXT_BASE", (intptr_t)text, probe, 64);
      if (!nz) { logf("    [KO] zone a zero\n"); st_read = ST_KO; }
    } else { logf("\n[4a] [KO] lecture TEXT_BASE echouee\n"); st_read = ST_KO; }

    memset(probe, 0xAA, sizeof(probe));
    if (kread((intptr_t)data, probe, sizeof(probe)) == 0) {
      int nz = 0;
      for (unsigned i = 0; i < sizeof(probe); i++) if (probe[i]) nz++;
      logf("\n[4b] lecture DATA_BASE : OK -- %d/64 octets non nuls\n", nz);
      hexdump("DATA_BASE", (intptr_t)data, probe, 64);
      if (!nz) { logf("    [KO] zone a zero\n"); st_read = ST_KO; }
    } else { logf("\n[4b] [KO] lecture DATA_BASE echouee\n"); st_read = ST_KO; }
  }

  /* ---- 4c : lecture reelle, mais role informatif ---- */
  if (!have_pipe) {
    logf("\n[4c] lecture SECURITY_FLAGS : non evalue\n");
    st_read_c = ST_NA;
  } else if (!(uintptr_t)KERNEL_ADDRESS_SECURITY_FLAGS) {
    logf("\n[4c] lecture SECURITY_FLAGS : IGNOREE, adresse nulle\n");
    logf("    => [4c] n'a pas ete teste. Elle est hors [4] et hors verdict.\n");
    st_read_c = ST_NA;
  } else {
    uint8_t b = 0xEE;
    if (kread((intptr_t)KERNEL_ADDRESS_SECURITY_FLAGS, &b, 1) == 0) {
      logf("\n[4c] octet SECURITY_FLAGS = 0x%02x\n", b);
      logf("    lecture noyau reelle, mais ROLE informatif : hors verdict.\n");
      st_read_c = ST_OK;
    } else {
      logf("\n[4c] [KO] lecture SECURITY_FLAGS echouee (hors verdict)\n");
      st_read_c = ST_KO;
    }
  }

  /* ---- 4d. parcours allproc : fin sur lien nul, comme le SDK ---- */
  if (!have_pipe) {
    logf("\n[4d] parcours allproc : non evalue (pas de prerequis)\n");
  } else if (!allproc) {
    logf("\n[4d] [KO] ALLPROC nul : echec, pas 'non evalue'\n");
    st_walk = st_pid = st_sdk = ST_KO;
  } else if ((allproc >> 48) != 0xffff) {
    logf("\n[4d] [KO] ALLPROC non canonique\n");
    st_walk = st_pid = st_sdk = ST_KO;
  } else {
    intptr_t p = 0, found = 0;
    int32_t  me = (int32_t)getpid();
    int      n = 0, trunc = 0, loop = 0, badptr = 0, badread = 0;

    logf("\n[4d] parcours allproc (max %d entrees), recherche du pid %d\n",
         WALK_MAX, (int)me);

    if (kread((intptr_t)allproc, &p, sizeof(p))) {
      logf("    [KO] lecture de la tete allproc echouee\n");
      st_walk = st_pid = st_sdk = ST_KO;
    } else {
      while (p && n < WALK_MAX) {
        int32_t  pid = -1;
        intptr_t nxt = 0;

        if ((p >> 48) != 0xffff) { logf("    [KO] proc non canonique\n"); badptr = 1; break; }
        if (kread(p + (intptr_t)KERNEL_OFFSET_PROC_P_PID, &pid, sizeof(pid))) {
          logf("    [KO] lecture p_pid echouee\n"); badread = 1; break;
        }

        logf("    +%03d  proc 0x%016lx  p_pid = %d\n", n, (unsigned long)p, (int)pid);

        if (!found && pid == me) found = p;

        if (kread(p, &nxt, sizeof(nxt))) {
          logf("    [KO] lecture du lien suivant echouee\n"); badread = 1; break;
        }
        if (nxt == p) { logf("    [!] boucle : lien auto-referent\n"); loop = 1; break; }

        p = nxt;
        n++;
      }

      if (p && n >= WALK_MAX) trunc = 1;

      if (badptr || badread || loop) {
        st_walk = ST_KO;
        logf("    [KO] parcours invalide (pointeur=%d lecture=%d boucle=%d)\n",
             badptr, badread, loop);
      } else if (trunc) {
        st_walk = ST_TRUNC;
        logf("    [!] liste tronquee a %d entrees, fin non atteinte\n", WALK_MAX);
      } else {
        st_walk = ST_OK;
        logf("    [OK] parcours termine sur lien nul (%d entrees)\n", n);
      }

      if (found) {
        st_pid = ST_OK;
        logf("    [OK] pid %d trouve a 0x%016lx\n", (int)me, (unsigned long)found);
      } else {
        st_pid = ST_KO;
        logf("    [KO] pid %d non trouve%s\n", (int)me,
             trunc ? " (tronque : absence NON concluante)" : "");
      }

      if (found) {
        intptr_t viaSdk = kernel_get_proc(me);
        logf("    recoupement SDK kernel_get_proc(%d) = 0x%016lx\n",
             (int)me, (unsigned long)viaSdk);
        if (viaSdk && viaSdk == found) {
          st_sdk = ST_OK;
          logf("    [OK] meme adresse. RECOUPEMENT, pas preuve independante :\n");
          logf("         les deux parcours tournent dans le meme environnement noyau.\n");
        } else {
          st_sdk = ST_KO;
          logf("    [KO] adresse differente ou nulle\n");
        }
      } else {
        st_sdk = ST_KO;
      }
    }
  }

#if PHASE >= 2
  if (!have_pipe) {
    logf("\n[5] scan : non evalue\n");
    st_scan = ST_NA;
  } else {
    anchors[0] = (anchor_t){ .name = "AES S-box",     .pat = pat_aes_sbox,  .len = 16 };
    anchors[1] = (anchor_t){ .name = "AES inv S-box", .pat = pat_aes_inv,   .len = 16 };
    anchors[2] = (anchor_t){ .name = "SHA-256 IV LE", .pat = pat_sha_iv_le, .len = 32 };
    anchors[3] = (anchor_t){ .name = "SHA-256 IV BE", .pat = pat_sha_iv_be, .len = 32 };

    logf("\n[5] execution du scan (text 32 Mo + data 8 Mo)\n");
    {
      int a = scan_region("TEXT", (intptr_t)text, SCAN_TEXT_SIZE, anchors, 4);
      int b = scan_region("DATA", (intptr_t)data, SCAN_DATA_SIZE, anchors, 4);
      st_scan = (a && b) ? ST_OK : ST_KO;
    }

    anchors_found = 0;
    for (unsigned i = 0; i < 4; i++) {
      if (anchors[i].found) {
        anchors_found++;
        logf("    [OK] %-14s -> 0x%016lx  (%s + 0x%lx | text_base + 0x%lx)\n",
             anchors[i].name,
             (unsigned long)(uintptr_t)anchors[i].hit,
             anchors[i].region,
             (unsigned long)((uintptr_t)anchors[i].hit -
                             (uintptr_t)anchors[i].region_base),
             (unsigned long)((uintptr_t)anchors[i].hit - text));
      } else {
        logf("    [--] %-14s non trouve\n", anchors[i].name);
      }
    }
  }
#endif

#if PHASE >= 3
  if (!have_pipe) { logf("\n[6] dump : non evalue\n"); st_dump = ST_NA; }
  else {
    logf("\n[6] dump brut\n");
    {
      int a = dump_region("kstuff_text.bin", (intptr_t)text, SCAN_TEXT_SIZE);
      int b = dump_region("kstuff_data.bin", (intptr_t)data, SCAN_DATA_SIZE);
      st_dump = (a && b) ? ST_OK : ST_KO;
    }
  }
#endif

  /* ---- resultats ---- */
  logf("\n=====================================================\n");
  logf(" RESULTATS (etats independants, aucun n'implique un autre)\n");
  logf("   [1] arguments + primitives ........... %s\n", st2s(st_args));
  logf("   [2] firmware lisible ................. %s\n", st2s(st_fw));
  logf("   [3] bases + ecarts conformes ......... %s\n", st2s(st_bases));
  logf("   [4] lectures brutes TEXT/DATA ........ %s   (retenu pour le verdict)\n",
       st2s(st_read));
  logf("   [4c] lecture SECURITY_FLAGS .......... %s   (role informatif)\n",
       st2s(st_read_c));
  logf("   [5] etat du parcours allproc ......... %s\n", st2s(st_walk));
  logf("   [6] pid du payload retrouve .......... %s\n", st2s(st_pid));
  logf("   [7] recoupement kernel_get_proc ...... %s   (pas preuve independante)\n",
       st2s(st_sdk));
#if PHASE >= 2
  logf("   [8] scan execute ..................... %s\n", st2s(st_scan));
  if (anchors_found >= 0)
    logf("   [9] ancres detectees ................. %d/4\n", anchors_found);
  else
    logf("   [9] ancres detectees ................. n/a\n");
#endif
#if PHASE >= 3
  logf("   [10] dump ............................ %s\n", st2s(st_dump));
#endif
  logf("-----------------------------------------------------\n");
  logf(" a lire avant d'interpreter :\n");
  logf("  - [4c] fait une VRAIE lecture noyau et peut reussir ; ce qui est\n");
  logf("    'hors verdict' est son ROLE, pas sa nature. 'non evalue' veut\n");
  logf("    dire IGNOREE (adresse nulle).\n");
  logf("  - [5] qualifie le PARCOURS, pas la presence du process.\n");
  logf("  - [6] est independant de [5]. [7] est un recoupement.\n");
#if PHASE >= 2
  logf("  - [8] dit que les lectures du scan sont terminees ; il ne dit\n");
  logf("    rien sur [9], qui compte les ancres effectivement trouvees.\n");
#endif
  logf("-----------------------------------------------------\n");
  logf(" DEFINITION DES NIVEAUX (identique au calcul)\n");
  logf("   FONCTIONNELLE      : [1][2][3][4] OK, [5] OK,     [6] OK, [7] OK\n");
  logf("   PARTIELLE          : [1][2][3][4] OK, [5] TRONQUE,[6] OK, [7] OK\n");
  logf("   PARTIELLE SANS PID : [1][2][3][4] OK, [5] TRONQUE,[6] KO, [7] KO\n");
  logf("   INCOMPLET          : tout autre cas\n");
  logf(" [4c] n'entre dans aucun niveau.\n");
  logf("-----------------------------------------------------\n");
  logf(" CODES DE SORTIE\n");
  logf("   %d = FONCTIONNELLE   %d = PARTIELLE\n", RC_FULL, RC_PARTIAL);
  logf("   %d = PARTIELLE SANS PID   %d = INCOMPLET\n", RC_NO_PID, RC_INCOMPLETE);
  logf("   (convention explicite : un niveau sans PID est un echec pour\n");
  logf("    un script appelant, d'ou un code non nul.)\n");
  logf("-----------------------------------------------------\n");

  base_ok = (st_args == ST_OK) && (st_fw == ST_OK) &&
            (st_bases == ST_OK) && (st_read == ST_OK);
  core_ok = base_ok && (st_pid == ST_OK) && (st_sdk == ST_OK);

  if (core_ok && st_walk == ST_OK)
    verdict = V_FULL;
  else if (core_ok && st_walk == ST_TRUNC)
    verdict = V_PARTIAL;
  else if (base_ok && st_walk == ST_TRUNC &&
           st_pid == ST_KO && st_sdk == ST_KO)
    verdict = V_NO_PID;
  else
    verdict = V_INCOMPLETE;

  if (verdict == V_FULL)
    logf(" VERDICT : FONCTIONNELLE.\n"
         "   [1] args, [2] firmware, [3] bases, [4] lectures, [5] parcours\n"
         "   complet, [6] pid, [7] recoupement : tous OK.\n"
         "   Validation fonctionnelle dans les conditions du test, avec les\n"
         "   adresses et structures definies par le SDK. Pas une preuve absolue.\n");
  else if (verdict == V_PARTIAL)
    logf(" VERDICT : PARTIELLE.\n"
         "   [1] a [4] OK, [6] et [7] OK : la lecture et la chaine pointeur\n"
         "   sont validees. Seul [5] est TRONQUE : la liste depassait %d\n"
         "   entrees, la fin n'a pas ete atteinte.\n", WALK_MAX);
  else if (verdict == V_NO_PID)
    logf(" VERDICT : PARTIELLE SANS PID.\n"
         "   [1] a [4] OK : la lecture noyau fonctionne. [5] TRONQUE et [6]\n"
         "   KO : le pid n'a pas ete atteint avant la limite, donc son\n"
         "   absence n'est PAS concluante. [7] KO en consequence.\n");
  else
    logf(" VERDICT : INCOMPLET.\n"
         "   Une condition necessaire a l'un des trois niveaux de validation\n"
         "   ci-dessus n'est pas satisfaite. Voir les statuts [1] a [7]\n"
         "   et les lignes [KO] / [TRONQUE] / non evalue.\n");
  logf("=====================================================\n");
  logf("\n C'EST FINI JOHNNY L'OGNION !\n");
  logf(" la tete de boule est en securite\n\n");

  if (g_fd >= 0) fsync(g_fd);

#if PHASE >= 2
  logf("[11] test isole : __syscall(599) sans argument\n");
  logf("     INDICE, pas conclusion : un arret ici peut aussi venir d'un\n");
  logf("     crash, d'un blocage, ou d'un probleme d'ecriture du journal.\n");
  logf("     Et __syscall(599) sans argument n'est PAS equivalent a l'appel\n");
  logf("     du SDK qui cible un PID via pt_syscall(pid, 599).\n");
  {
    long r = (long)__syscall(599);
    logf("     retour = %ld  errno = %d\n", r, errno);
  }
  logf("[12] marqueur final : si cette ligne existe, l'appel 599 est revenu.\n");
#endif

  if (g_fd >= 0) { fsync(g_fd); close(g_fd); g_fd = -1; }

  switch (verdict) {
  case V_FULL:    rc = RC_FULL;    break;
  case V_PARTIAL: rc = RC_PARTIAL; break;
  case V_NO_PID:  rc = RC_NO_PID;  break;
  default:        rc = RC_INCOMPLETE;
  }
  return rc;
}
