#pragma once
#include <fltKernel.h>


struct _Process;
typedef _Process* pProcess;

typedef struct _DeletedData
{
	PVOID Content;
	ULONG Size;
	double PreEntropy;
}DeletedData, * pDeletedData;

typedef struct _DeletedFile
{
	UNICODE_STRING Filename;
	PVOID Content;
	ULONG Size;
	double PreEntropy;
	LIST_ENTRY* Next;
}DeletedFile, * pDeletedFile;

namespace files
{
	bool AddDeletedFile(PUNICODE_STRING Filename, PVOID Content, ULONG Size, ULONG Pid, double PreEntropy);
	void ReleaseDeletedFiles(pProcess ProcessEntry);
	bool RemoveDeletedFile(pDeletedFile OldDeletedFile, pProcess ProcessEntry, bool Locked);
	bool RemoveDeletedFileByName(PUNICODE_STRING FileName, ULONG Pid);

	DeletedData GetDeletedFileContent(PUNICODE_STRING Filename, ULONG Pid);
}