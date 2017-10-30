#include "winmem.h"

int main()
{
  win_init ();

  void* p;
/*
  p = win_alloc (WriteAccess, 123);
  win_free (WriteAccess, p);
  p = win_alloc (WriteAccess, 46);
  win_free (WriteAccess, p);
*/
  p = win_alloc (ReadAccess, 1234);
  win_free (ReadAccess, p);

  win_deinit ();
}