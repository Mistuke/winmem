#include <stddef.h>

typedef enum _AccessType {
    ReadAccess = 0x1,
    WriteAccess = 0x2,
    ExecuteAccess = 0x4
} AccessType;

void win_init ();
void win_deinit ();

void* win_alloc (AccessType type, size_t n);
void win_free (AccessType type, void* memptr);