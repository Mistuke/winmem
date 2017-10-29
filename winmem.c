#include <tlsf.h>
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include "winmem.h"

#if MEM_DEBUG
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
  pool_t m_pool;
  tlsf_t m_alloc;
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

const int pool_resize_limit = 10;
const int default_pages_allocate = 15;
static bool initialized = false;

size_t getPageSize (void)
{
  static size_t pagesize = 0;

  if (pagesize == 0) {
      SYSTEM_INFO sSysInfo;
      GetSystemInfo(&sSysInfo);
      pagesize = sSysInfo.dwPageSize;
      IF_DEBUG (printf("** pagesize: %zu\n", pagesize));
  }

  return pagesize;
}

uint64_t findManager (AccessType type)
{
  for (int x = 0; x < NUM_ACCESS; x++)
    if (map[x].mask == type) {
      return map[x].index;
    }

  return -1;
}

void addPoolBuffer (size_t size, void* buffer, pool_t pool, tlsf_t manager)
{
  PoolBuffer* m_buffer = malloc (sizeof(PoolBuffer));
  assert (m_buffer);
  m_buffer->size    = size;
  m_buffer->buffer  = buffer;
  m_buffer->m_pool  = pool;
  m_buffer->m_alloc = manager;
  m_buffer->next    = buffers;
  buffers = m_buffer;
  IF_DEBUG (printf (" $ Pool created. { size=%zu, buffer=%p, pool=%p, manager=%p } \n", size, buffer, pool, manager));
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

  for (PoolBuffer* b = buffers; b; ) {
    IF_DEBUG (printf (" $ pool %p destroyed in manager %p.\n", b->m_pool, b->m_alloc));
    tlsf_remove_pool (b->m_alloc, b->m_pool);
    VirtualFree (b->buffer, 0, MEM_RELEASE);
    PoolBuffer* tmp = b->next;
    free (b);
    b = tmp;
  }

  for (int x = 0; x < NUM_ACCESS; x++)
      if (mem_manager[x]) {
          tlsf_destroy (mem_manager[x]);
          IF_DEBUG (printf ("** destroyed managed %p.\n", mem_manager[x]));
          mem_manager[x] = NULL;
      }

  IF_DEBUG (printf ("** memory manager un-initialized.\n"));
}

static size_t getAllocSize (size_t requested)
{
  size_t overhead = tlsf_size() + tlsf_pool_overhead()
                  + tlsf_alloc_overhead();
  size_t pageSize = getPageSize ();
  size_t gAlloc = pageSize * default_pages_allocate;
  if (requested > (gAlloc - overhead)) {
    gAlloc = requested + overhead;
    // Now round up to next page size.
    int pages = gAlloc / pageSize;
    int overflow = pages * pageSize;
    if (gAlloc > overflow)
      pages++;
    gAlloc = pages * pageSize;
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

void* win_alloc (AccessType type, size_t n)
{
  uint64_t index = findManager (type);
  tlsf_t manager = mem_manager[index];

  if (!manager) {
    size_t m_size = getAllocSize (n);
    uint64_t m_protect = getProtection (type);
    void* cache
      = VirtualAlloc (NULL, m_size, MEM_COMMIT | MEM_RESERVE, m_protect);
    if (!cache)
      return NULL;

    manager = tlsf_create_with_pool (cache, m_size);
    assert (manager);
    pool_t m_pool = tlsf_get_pool (manager);
    mem_manager[index] = manager;
    addPoolBuffer (m_size, cache, m_pool, manager);
    IF_DEBUG (printf ("- new manager %p created with size %zu (%zu) with pool %p at %p with protection %llu.\n",
                      manager, m_size, n, m_pool, cache, m_protect));
  }

  void* result = tlsf_malloc (manager, n);
  if (!result) {
    /* We've failed first allocation, probably don't have enough free memory.
       Let's resize.  */
    size_t m_size = getAllocSize (n);
    uint64_t m_protect = getProtection (type);
    void* cache
      = VirtualAlloc (NULL, m_size, MEM_COMMIT | MEM_RESERVE, m_protect);
    if (!cache)
      return NULL;

    pool_t m_pool = tlsf_add_pool (manager, cache, m_size);
    addPoolBuffer (m_size, cache, m_pool, manager);
    result = tlsf_malloc (manager, n);
  }

  return result;
}

void win_free (AccessType type, void* memptr)
{
  uint64_t index = findManager (type);
  tlsf_t manager = mem_manager[index];
  assert (manager);
  tlsf_free (manager, memptr);
  IF_DEBUG (printf ("- freed %p of type %d from manager %p.\n", memptr, type, manager));
}