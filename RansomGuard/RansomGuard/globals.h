#pragma once
#include <fltKernel.h>
#include "Mutex.h"

extern PFLT_FILTER gFilterHandle;
extern PFLT_PORT FilterPort;
extern PFLT_PORT SendClientPort;
extern Mutex ProcessesListMutex;
extern EX_RUNDOWN_REF PendingOps;
