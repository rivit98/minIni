/*
 * A tiny in-memory file system behind minGlue.h.
 *
 * VFS_FILES named files, each a heap buffer sized exactly to its contents, so
 * ASAN sees any read past the end. Handles mimic stdio: fgets() semantics for
 * vfs_gets(), "wb" truncates, "r+b" overwrites in place. vfs_reset() frees
 * everything at the end of each exec (per-input leak checks stay clean).
 */
#ifndef FUZZ_VFS_H
#define FUZZ_VFS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define VFS_FILES    4
#define VFS_NAME_MAX 64
#define VFS_MAX_SIZE (1u << 20)   /* a write past this fails, like a full disk */

enum vfs_mode { VFS_READ, VFS_WRITE, VFS_REWRITE };

struct vfs_file {
  bool used;
  char name[VFS_NAME_MAX];
  char *buf;
  size_t len;
};

struct vfs_handle {
  struct vfs_file *f;
  size_t pos;
  enum vfs_mode mode;
};

static struct vfs_file vfs[VFS_FILES];

static struct vfs_file *vfs_find(const char *name)
{
  for (int i = 0; i < VFS_FILES; i++)
    if (vfs[i].used && strcmp(vfs[i].name, name) == 0)
      return &vfs[i];
  return NULL;
}

static struct vfs_file *vfs_create(const char *name)
{
  struct vfs_file *f = vfs_find(name);

  if (f)
    return f;
  if (strlen(name) >= VFS_NAME_MAX)
    return NULL;
  for (int i = 0; i < VFS_FILES; i++)
    if (!vfs[i].used) {
      vfs[i].used = true;
      strcpy(vfs[i].name, name);
      vfs[i].buf = NULL;
      vfs[i].len = 0;
      return &vfs[i];
    }
  return NULL;
}

static void vfs_unlink(struct vfs_file *f)
{
  free(f->buf);
  memset(f, 0, sizeof(*f));
}

static void vfs_reset(void)
{
  for (int i = 0; i < VFS_FILES; i++)
    if (vfs[i].used)
      vfs_unlink(&vfs[i]);
}

/* store @data as file @name, replacing it */
static bool vfs_store(const char *name, const char *data, size_t len)
{
  struct vfs_file *f = vfs_create(name);

  if (!f)
    return false;
  free(f->buf);
  f->buf = len ? malloc(len) : NULL;
  if (len)
    memcpy(f->buf, data, len);
  f->len = len;
  return true;
}

static bool vfs_open(const char *name, struct vfs_handle *h, enum vfs_mode mode)
{
  struct vfs_file *f = mode == VFS_WRITE ? vfs_create(name) : vfs_find(name);

  if (!f)
    return false;
  if (mode == VFS_WRITE) {
    free(f->buf);
    f->buf = NULL;
    f->len = 0;
  }
  h->f = f;
  h->pos = 0;
  h->mode = mode;
  return true;
}

static bool vfs_close(struct vfs_handle *h)
{
  h->f = NULL;
  return true;
}

/* fgets(): up to size-1 bytes, stops after '\n', NUL-terminates */
static bool vfs_gets(char *buf, int size, struct vfs_handle *h)
{
  struct vfs_file *f = h->f;
  size_t n = 0;

  if (!f || size <= 0 || h->pos >= f->len)
    return false;
  while (n + 1 < (size_t)size && h->pos < f->len) {
    char c = f->buf[h->pos++];
    buf[n++] = c;
    if (c == '\n')
      break;
  }
  buf[n] = '\0';
  return true;
}

static bool vfs_puts(const char *s, struct vfs_handle *h)
{
  struct vfs_file *f = h->f;
  size_t n = strlen(s), end;

  if (!f || h->mode == VFS_READ)
    return false;
  end = h->pos + n;
  if (end > VFS_MAX_SIZE)
    return false;
  if (end > f->len) {
    char *nb = realloc(f->buf, end);
    if (!nb)
      return false;
    f->buf = nb;
    f->len = end;
  }
  memcpy(f->buf + h->pos, s, n);
  h->pos = end;
  return true;
}

static bool vfs_seek(struct vfs_handle *h, size_t pos)
{
  if (!h->f || pos > h->f->len)
    return false;
  h->pos = pos;
  return true;
}

static bool vfs_rename(const char *src, const char *dst)
{
  struct vfs_file *s = vfs_find(src), *d;

  if (!s || strlen(dst) >= VFS_NAME_MAX)
    return false;
  d = vfs_find(dst);
  if (d && d != s)
    vfs_unlink(d);
  strcpy(s->name, dst);
  return true;
}

static bool vfs_remove(const char *name)
{
  struct vfs_file *f = vfs_find(name);

  if (!f)
    return false;
  vfs_unlink(f);
  return true;
}

#endif
