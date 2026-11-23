/*
 * minIni fuzz harness (LLVMFuzzerTestOneInput; afl-cc links libAFLDriver).
 *
 * Input: 4-byte flag seed, then the INI file text. The seed drives a PRNG
 * that picks buffer sizes, operations and their arguments; the text is
 * stored as file "f.ini" in the in-memory file system (fuzz_vfs.h).
 *
 * minIni.c is #included (the copy CMake places next to the fuzz glue), so its
 * asserts are live: NDEBUG is never defined for it.
 *
 * Groups (TC= selects a group or one test case):
 *   test_read   ini_browse, ini_gets/getl/getbool/getf, has*, getsection/getkey
 *   test_write  ini_puts/putl/putbool/putf and deletions, with a read-back oracle
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "minIni.c"

#define FILE_NAME "f.ini"

/* ── flags ─────────────────────────────────────────────────────────────── */

struct flags_t {
  uint32_t seed;
  uint64_t rng;
};

static void setup_flags(uint32_t seed, struct flags_t *flags)
{
  flags->seed = seed;
  flags->rng = 0x9e3779b97f4a7c15ULL ^ seed;
}

static uint32_t rnd(struct flags_t *fl)
{
  /* splitmix64 */
  uint64_t z = (fl->rng += 0x9e3779b97f4a7c15ULL);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return (uint32_t)(z ^ (z >> 31));
}

/* a buffer size: mostly small edge cases, sometimes the full INI_BUFFERSIZE */
static int pick_size(struct flags_t *fl)
{
  switch (rnd(fl) % 4) {
  case 0:  return 1 + rnd(fl) % 4;
  case 1:  return 1 + rnd(fl) % 32;
  case 2:  return 1 + rnd(fl) % INI_BUFFERSIZE;
  default: return INI_BUFFERSIZE;
  }
}

/* ── TC selection, VERBOSE ─────────────────────────────────────────────── */

static const char *tc_filter;
static bool tc_filter_matched;
static bool tc_group_all = true;
static bool verbose;
static bool roundtrip;   /* FUZZ_ROUNDTRIP=1: put/get oracle, see test_modify */

__attribute__((constructor)) static void init_common(void)
{
  verbose = getenv("VERBOSE") != NULL;
  roundtrip = getenv("FUZZ_ROUNDTRIP") != NULL;
  tc_filter = getenv("TC");
  if (tc_filter && !*tc_filter)
    tc_filter = NULL;
}

static bool tc_selected(const char *name, signed char *cache, bool group)
{
  if (__builtin_expect(tc_filter == NULL, 1))
    return true;
  if (*cache < 0) {
    *cache = strcmp(tc_filter, name) == 0;
    tc_filter_matched |= (bool)*cache;
  }
  if (group) {
    tc_group_all = (bool)*cache;
    return true;   /* entered anyway: TC may name a member */
  }
  return *cache || tc_group_all;
}

#define T(func) do { \
  static signed char _sel = -1; \
  if (!tc_selected(#func, &_sel, false)) break; \
  if (verbose) fprintf(stderr, "=== Running %s ===\n", #func); \
  func(flags, data, size); \
} while (0)

#define G(func) do { \
  static signed char _sel = -1; \
  tc_selected(#func, &_sel, true); \
  func(flags, data, size); \
} while (0)

/* ── helpers ───────────────────────────────────────────────────────────── */

#define MAX_ENTRIES 32

struct entry {
  char section[INI_BUFFERSIZE];
  char key[INI_BUFFERSIZE];
  char value[INI_BUFFERSIZE];
};

struct entries {
  int n;
  struct entry e[MAX_ENTRIES];
};

static int collect_cb(const char *section, const char *key, const char *value, void *user)
{
  struct entries *es = user;

  if (es->n >= MAX_ENTRIES)
    return 0;
  struct entry *e = &es->e[es->n++];
  snprintf(e->section, sizeof(e->section), "%s", section);
  snprintf(e->key, sizeof(e->key), "%s", key);
  snprintf(e->value, sizeof(e->value), "%s", value);
  return 1;
}

static void load_input(const char *data, size_t size)
{
  vfs_reset();
  vfs_store(FILE_NAME, data, size);
}

/* exactly-sized heap buffers, so ASAN sees a one-byte overflow */
static void probe_gets(struct flags_t *fl, const char *section, const char *key)
{
  int sz = pick_size(fl);
  char *buf = malloc(sz);
  const char *def = (rnd(fl) & 1) ? "default-value-xyz" : "";

  int n = ini_gets(section, key, def, buf, sz, FILE_NAME);
  if (n < 0 || n >= sz || strlen(buf) != (size_t)n) {
    fprintf(stderr, "ini_gets returned %d for a %d-byte buffer\n", n, sz);
    abort();
  }
  free(buf);
}

static void probe_enum(struct flags_t *fl, const char *section)
{
  for (int i = 0; i < MAX_ENTRIES; i++) {
    int sz = pick_size(fl);
    char *buf = malloc(sz);
    int n = ini_getkey(section, i, buf, sz, FILE_NAME);
    free(buf);
    if (n == 0)
      break;
  }
}

/* ── test cases ────────────────────────────────────────────────────────── */

static void test_browse(struct flags_t *flags, const char *data, size_t size)
{
  struct entries es = {0};

  load_input(data, size);
  ini_browse(collect_cb, &es, FILE_NAME);

  for (int i = 0; i < es.n; i++) {
    struct entry *e = &es.e[i];
    probe_gets(flags, e->section, e->key);
    (void)ini_getl(e->section, e->key, -1, FILE_NAME);
    (void)ini_getbool(e->section, e->key, -1, FILE_NAME);
    (void)ini_getf(e->section, e->key, 0.5f, FILE_NAME);
    (void)ini_haskey(e->section, e->key, FILE_NAME);
    (void)ini_hassection(e->section, FILE_NAME);
  }
}

static void test_enumerate(struct flags_t *flags, const char *data, size_t size)
{
  load_input(data, size);
  probe_enum(flags, "");
  for (int i = 0; i < MAX_ENTRIES; i++) {
    int sz = pick_size(flags);
    char *sec = malloc(sz);
    int n = ini_getsection(i, sec, sz, FILE_NAME);
    if (n > 0)
      probe_enum(flags, sec);
    free(sec);
    if (n == 0)
      break;
  }
}

/* the raw input as section and key names: lines that are not entries */
static void test_lookup_lines(struct flags_t *flags, const char *data, size_t size)
{
  char *copy = malloc(size + 1);
  char *lines[8];
  int nl = 0;

  memcpy(copy, data, size);
  copy[size] = '\0';
  for (char *p = strtok(copy, "\r\n"); p && nl < 8; p = strtok(NULL, "\r\n"))
    lines[nl++] = p;

  load_input(data, size);
  for (int i = 0; i < nl; i++) {
    const char *sec = lines[rnd(flags) % nl];
    probe_gets(flags, sec, lines[i]);
    probe_gets(flags, NULL, lines[i]);
    (void)ini_haskey(sec, lines[i], FILE_NAME);
    (void)ini_hassection(lines[i], FILE_NAME);
  }
  free(copy);
}

/*
 * Simple strings survive a put/get round trip unchanged; for those, a put
 * that reports success and a get that disagrees is a bug - except that
 * duplicate sections/keys and over-long lines legitimately break it, so it is
 * off unless FUZZ_ROUNDTRIP=1 (the 2-lane smoke run: dozens of such hits/min).
 */
static bool simple(const char *s, size_t max)
{
  size_t n = strlen(s);

  if (n == 0 || n >= max || s[0] == ' ' || s[n - 1] == ' ')
    return false;
  for (; *s; s++)
    if (*s < 0x21 || *s > 0x7e || strchr("[]=:;#\"\\'", *s))
      return false;
  return true;
}

static const char *pick_str(struct flags_t *fl, struct entries *es, int which)
{
  static const char *fixed[] = { "", "s", "key", "a b", "x=y", "[q]", ";c", "\"q\"", "123", "-7" };

  if (es->n == 0 || rnd(fl) % 4 == 0)
    return fixed[rnd(fl) % (sizeof(fixed) / sizeof(fixed[0]))];
  struct entry *e = &es->e[rnd(fl) % es->n];
  switch (which == 3 ? rnd(fl) % 3 : (unsigned)which) {
  case 0:  return e->section;
  case 1:  return e->key;
  default: return e->value;
  }
}

static void test_modify(struct flags_t *flags, const char *data, size_t size)
{
  struct entries es = {0};
  int ops = 1 + rnd(flags) % 6;

  load_input(data, size);
  ini_browse(collect_cb, &es, FILE_NAME);

  for (int i = 0; i < ops; i++) {
    const char *sec = pick_str(flags, &es, (rnd(flags) & 3) ? 0 : 3);
    const char *key = pick_str(flags, &es, (rnd(flags) & 3) ? 1 : 3);
    const char *val = pick_str(flags, &es, 3);
    int r;

    switch (rnd(flags) % 8) {
    case 0: case 1: case 2:
      r = ini_puts(sec, key, val, FILE_NAME);
      if (roundtrip && r && simple(sec, 64) && simple(key, 64) && simple(val, 64)) {
        char buf[INI_BUFFERSIZE];
        ini_gets(sec, key, "", buf, sizeof(buf), FILE_NAME);
        if (strcmp(buf, val) != 0) {
          fprintf(stderr, "round trip: put [%s] %s=%s, got '%s'\n", sec, key, val, buf);
          abort();
        }
      }
      break;
    case 3: (void)ini_putl(sec, key, (long)(int32_t)rnd(flags), FILE_NAME); break;
    case 4: (void)ini_putbool(sec, key, rnd(flags) & 1, FILE_NAME); break;
    case 5: {
      float v;
      uint32_t bits = rnd(flags);
      memcpy(&v, &bits, sizeof(v));
      (void)ini_putf(sec, key, v, FILE_NAME);
      break;
    }
    case 6: (void)ini_puts(sec, key, NULL, FILE_NAME); break;   /* delete key */
    case 7: (void)ini_puts(sec, NULL, NULL, FILE_NAME); break;  /* delete section */
    }
  }

  /* read the result back through every reader */
  struct entries after = {0};
  ini_browse(collect_cb, &after, FILE_NAME);
  for (int i = 0; i < after.n; i++)
    probe_gets(flags, after.e[i].section, after.e[i].key);
}

/* ── groups ────────────────────────────────────────────────────────────── */

static void test_read(struct flags_t *flags, const char *data, size_t size)
{
  T(test_browse);
  T(test_enumerate);
  T(test_lookup_lines);
}

static void test_write(struct flags_t *flags, const char *data, size_t size)
{
  T(test_modify);
}

/* ── entry points ──────────────────────────────────────────────────────── */

int LLVMFuzzerTestOneInput(const uint8_t *in, size_t insize);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  static const uint8_t warm[] = "\0\0\0\0[s]\nkey=value\n";

  (void)argc;
  (void)argv;
  /* first-time paths (stdio, strtod locale data) belong to no exec */
  LLVMFuzzerTestOneInput(warm, sizeof(warm) - 1);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *in, size_t insize)
{
  struct flags_t _flags;
  struct flags_t *flags = &_flags;
  uint32_t seed;

  if (insize <= sizeof(uint32_t))
    return 0;
  memcpy(&seed, in, sizeof(seed));
  setup_flags(seed, flags);
  const char *data = (const char *)in + sizeof(uint32_t);
  size_t size = insize - sizeof(uint32_t);

  G(test_read);
  G(test_write);
  vfs_reset();

  if (__builtin_expect(tc_filter != NULL, 0) && !tc_filter_matched) {
    fprintf(stderr, "TC=%s does not name any test case\n", tc_filter);
    exit(1);
  }

#ifdef __AFL_LEAK_CHECK
  __AFL_LEAK_CHECK();
#endif
  return 0;
}

#if defined REPRODUCER
#include <dlfcn.h>

#define CONCAT2(a, b) a##b
#define CONCAT(a, b) CONCAT2(a, b)

static size_t read_artifact_raw(const char *path, char **out)
{
  int fd = open(path, O_RDONLY);
  struct stat st;

  if (fd < 0 || fstat(fd, &st) < 0) { perror(path); exit(1); }
  *out = NULL;
  if (st.st_size == 0) { close(fd); return 0; }
  *out = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (*out == MAP_FAILED) { perror("mmap"); exit(1); }
  return st.st_size;
}

/* RR(n, path): print the RF() text for an artifact, then run it */
#define RR(nr, artifact_path) \
int CONCAT(vc, nr)(void) { \
  char *d; \
  size_t n = read_artifact_raw(artifact_path, &d); \
  if (n > sizeof(uint32_t)) { \
    uint32_t s; memcpy(&s, d, 4); \
    printf("RF(%d, test_func, 0x%08xu, \"", nr, s); \
    for (size_t i = 4; i < n; i++) printf("\\x%02x", (unsigned char)d[i]); \
    printf("\", %zu)\n", n - 4); \
    fflush(stdout); \
    LLVMFuzzerTestOneInput((const uint8_t *)d, n); \
    munmap(d, n); \
  } \
  return n > 0; \
}

/* RF(n, func, seed, "data", len): one test case, one seed, standalone */
#define RF(nr, func, seed_, data_, n_) \
int CONCAT(tc, nr)(void) { \
  struct flags_t _f; setup_flags((seed_), &_f); \
  func(&_f, (data_), (n_)); \
  vfs_reset(); \
  return 0; \
}

/* harvested test cases go here, e.g.  RR(1, "/path/to/crash")  */

static int run_input_file(const char *path)
{
  struct stat st;
  if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
    return -1;
  char *d;
  size_t n = read_artifact_raw(path, &d);
  uint8_t *copy = malloc(n ? n : 1);   /* heap copy: ASAN sees overreads */
  if (n) memcpy(copy, d, n);
  if (n) munmap(d, n);
  LLVMFuzzerTestOneInput(copy, n);
  free(copy);
  return 0;
}

int main(int argc, char **argv)
{
  int i, n = 0;

  if (argc < 2) {
    printf("Usage: %s <input-file>... | <testcase>\n", argv[0]);
    return 1;
  }
  LLVMFuzzerInitialize(&argc, &argv);
  for (i = 1; i < argc; i++) {
    if (run_input_file(argv[i]) == 0) { n++; continue; }
    void *sym = dlsym(dlopen(NULL, RTLD_NOW), argv[i]);
    if (!sym) { printf("no input file or test case '%s'\n", argv[i]); return 1; }
    return ((int (*)(void))sym)();
  }
  fprintf(stderr, "%s: ran %d input(s)\n", argv[0], n);
  return 0;
}
#endif /* REPRODUCER */
