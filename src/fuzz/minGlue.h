/*
 * minIni glue for fuzzing: an in-memory file system (fuzz_vfs.h).
 *
 * CMakeLists.txt copies dev/minIni.c next to this file (as minGlue.h) in the
 * build tree, so minIni.c's #include "minGlue.h" picks this one up instead of
 * the stdio glue in dev/. No disk I/O: every exec is self-contained, and
 * ini_puts()'s temp-file + rename dance runs against fuzz_vfs.
 */
#ifndef FUZZ_MINGLUE_H
#define FUZZ_MINGLUE_H

#include <stdio.h>
#include <stdlib.h>
#include "fuzz_vfs.h"

#define INI_FILETYPE                    struct vfs_handle
#define ini_openread(filename,file)     vfs_open((filename), (file), VFS_READ)
#define ini_openwrite(filename,file)    vfs_open((filename), (file), VFS_WRITE)
#define ini_openrewrite(filename,file)  vfs_open((filename), (file), VFS_REWRITE)
#define ini_close(file)                 vfs_close(file)
#define ini_read(buffer,size,file)      vfs_gets((buffer), (size), (file))
#define ini_write(buffer,file)          vfs_puts((buffer), (file))
#define ini_rename(source,dest)         vfs_rename((source), (dest))
#define ini_remove(filename)            vfs_remove(filename)

#define INI_FILEPOS                     size_t
#define ini_tell(file,p)                (*(p) = (file)->pos)
#define ini_seek(file,p)                vfs_seek((file), *(p))

/* same as the stdio glue: the buffer overflow, if any, is upstream's */
#define INI_REAL                        float
#define ini_ftoa(string,value)          sprintf((string),"%f",(value))
#define ini_atof(string)                (INI_REAL)strtod((string),NULL)

#endif
