#include <tlsf.h>
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include "winmem.h"

#ifdef MEM_DEBUG
#include <stdio.h>
#define IF_DEBUG(X) X
#else
#define IF_DEBUG(X)
#endif

typedef struct _AccessMap
{
  uint64_t mask;
  uint64_t index;
  uint64_t access;
} AccessMap;

typedef struct _PoolBuffer
{
  size_t size;
  void* buffer;
  tlsf_t m_alloc;
  uint32_t m_flags;
  struct _PoolBuffer* next;
} PoolBuffer;

AccessMap map[] = {
  { ReadAccess                              , 0, PAGE_READONLY          },
  { WriteAccess                             , 1, PAGE_READWRITE         },
  { ReadAccess | WriteAccess                , 1, PAGE_READWRITE         },
  { ExecuteAccess                           , 2, PAGE_EXECUTE           },
  { ReadAccess | ExecuteAccess              , 3, PAGE_EXECUTE_READ      },
  { ReadAccess | WriteAccess | ExecuteAccess, 4, PAGE_EXECUTE_READWRITE }
 };

enum { NUM_ACCESS = sizeof(map) / sizeof (AccessMap) };
static tlsf_t mem_manager[NUM_ACCESS];
static PoolBuffer* buffers = NULL;

const size_t pool_resize_limit = 10;
const size_t default_blocks_allocate = 15;
static bool initialized = false;
static bool m_enforcing_mem_protect = false;

size_t getAllocationSize (void)
{
  static size_t allocsize = 0;

  if (allocsize == 0) {
      SYSTEM_INFO sSysInfo;
      GetSystemInfo(&sSysInfo);
      allocsize = sSysInfo.dwAllocationGranularity;
      IF_DEBUG (printf("** allocsize: %zu bytes\n", allocsize));
  }

  return allocsize;
}

uint64_t findManager (AccessType type)
{
  for (int x = 0; x < NUM_ACCESS; x++)
    if (map[x].mask == type) {
      return map[x].index;
    }

  return (uint64_t)-1;
}

static size_t getAllocSize (size_t requested)
{
  size_t allocsize = getAllocationSize ();
  size_t gAlloc = allocsize * default_blocks_allocate;
  if (requested > gAlloc) {
    gAlloc = requested;
    /* Now round up to next page size to keep aligned to the page boundary.  */
    size_t pages = gAlloc / allocsize;
    size_t overflow = pages * allocsize;
    if (gAlloc > overflow)
      pages++;
    gAlloc = pages * allocsize;
  }

  return gAlloc;
}

static uint64_t getProtection (AccessType type)
{
  for (int x = 0; x < NUM_ACCESS; x++)
    if (map[x].mask == type) {
      return map[x].access;
    }

  return PAGE_NOACCESS;
}

void* win_cback_map (size_t* size, void* user)
{
  /* We've failed first allocation, probably don't have enough free memory.
     Let's resize.  */
     size_t m_size = getAllocSize (*size);
     DWORD m_protect = (DWORD)getProtection ((AccessType)user);
     void* cache
       = VirtualAlloc (NULL, m_size, MEM_COMMIT | MEM_RESERVE,
             m_enforcing_mem_protect ? m_protect : PAGE_EXECUTE_READWRITE);
     //IF_DEBUG (printf ("+ resized manager %p adding %zu bytes (%zu) with pool %p at %p with protection %llu.\n",
     //manager, m_size, *size, m_pool, cache, m_protect));
     *size = m_size;
     return cache;
}

void win_cback_unmap (void* mem, size_t size, void* user)
{
  (void)user;
  VirtualFree (mem, 0, (DWORD)size);
}

void win_init ()
{
  IF_DEBUG (printf ("** memory manager initialized.\n"));
  IF_DEBUG (printf ("** using %d access steams.\n", NUM_ACCESS));
  initialized = true;
}

void win_deinit ()
{
  if (!initialized)
    return;

  for (int x = 0; x < NUM_ACCESS; x++)
      if (mem_manager[x]) {
          tlsf_destroy (mem_manager[x]);
          IF_DEBUG (printf ("** destroyed managed %p.\n", mem_manager[x]));
          mem_manager[x] = NULL;
      }

  IF_DEBUG (printf ("** memory manager un-initialized.\n"));
}

void* win_alloc (AccessType type, size_t n)
{
  if (!initialized)
    return NULL;

  uint64_t index = findManager (type);
  tlsf_t manager = mem_manager[index];

  if (!manager)
    {
      manager = tlsf_create (win_cback_map, win_cback_unmap, (void*)type);
      mem_manager[index] = manager;
    }

  void* result = tlsf_malloc (manager, n);
  IF_DEBUG (printf ("-> allocated %zu bytes.\n", n));

  return result;
}

void win_free (AccessType type, void* memptr)
{
  if (!initialized)
    return;

  uint64_t index = findManager (type);
  tlsf_t manager = mem_manager[index];
  assert (manager);
  tlsf_free (manager, memptr);
  IF_DEBUG (printf ("- freed %p of type %d from manager %p.\n", memptr, type, manager));
}

void win_memory_protect ()
{
  if (!initialized)
    return;

  m_enforcing_mem_protect = true;

  for (PoolBuffer* b = buffers; b; b = b->next ) {
    //IF_DEBUG (printf (" $ pool %p protected (0x%llx) in manager %p.\n", b->m_pool, b->m_flags, b->m_alloc));
    /* Note: Abort if this fails when added to GHC.  */
    DWORD old_flags;
    VirtualProtect (b->buffer, b->size, b->m_flags, &old_flags);
  }
}

void win_memory_unprotect ()
{
  if (!initialized)
    return;

  m_enforcing_mem_protect = false;

  for (PoolBuffer* b = buffers; b; b = b->next) {
    //IF_DEBUG (printf (" $ pool %p un-protected (RW) in manager %p.\n", b->m_pool, b->m_alloc));
    /* Note: Abort if this fails when added to GHC.  */
    DWORD old_flags;
    VirtualProtect (b->buffer, b->size, PAGE_EXECUTE_READWRITE, &old_flags);
  }
}