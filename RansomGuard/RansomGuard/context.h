#pragma once
#include <fltKernel.h>
#include "Mutex.h"

#define FLT_CUSTOM_TYPE 0x07
#define FLT_CREATE_CONTEXT 0x08
#define FLT_NO_CONTEXT 0x09

typedef struct _CreateCompletionContext
{
	bool Truncated;
	bool DeleteOnClose;
	bool SavedContent;
	bool CalculatedEntropy;
	ULONG InitialFileSize;
	PVOID OriginalContent;
	double PreEntropy;

}CreateCompletionContext, * pCreateCompletionContext;

typedef struct _HandleContext
{
	PFLT_FILTER Filter;
	PFLT_INSTANCE Instance;
	UNICODE_STRING FileName;
	UNICODE_STRING FinalComponent;
	ULONG RequestorPid;
	bool WriteOccured;
	bool SavedContent;
	bool CcbDelete;
	bool Truncated;
	bool FcbDelete;
	bool NewFile;
	int  NumSetInfoOps;
	double PreEntropy;
	double PostEntropy;
	PVOID OriginalContent;
	ULONG InitialFileSize;
}HandleContext, * pHandleContext;

typedef struct _FileContext
{
	UNICODE_STRING FileName;
	UNICODE_STRING FinalComponent;
} FileContext, * pFileContext ;





