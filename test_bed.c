#include "winmem.h"
#include <stdio.h>
#include <string.h>

int main()
{
  win_init ();
  win_memory_protect ();
  void* p;

  printf ("@ Creating ReadWrite area.\n\n");
  p = win_alloc (WriteAccess, 1882384);
  win_free (WriteAccess, p);
  p = win_alloc (WriteAccess, 46);

  win_memory_protect ();

  printf ("@ Writing 40 bytes to RW area.\n\n");
  memset (p, 0xFF, 40);

  win_memory_unprotect ();
  win_free (WriteAccess, p);

  printf ("@ Creating Read-only area.\n\n");
  p = win_alloc (ReadAccess, 1234);
  win_memory_protect ();

  printf ("@ Writing 40 bytes to R area (should crash).\n\n");
  memset (p, 0xFF, 40);

  printf (":: %p\n", p);
  memset (p, 0xFF, 40);
  win_memory_unprotect ();
  win_free (ReadAccess, p);
  win_deinit ();
}