#pragma once
#include <fltKernel.h>

struct _Process;
typedef _Process* pProcess;

typedef struct _Section
{
	UNICODE_STRING Filename;
	LIST_ENTRY* Next;
}Section, * pSection;


namespace sections
{
	void ReleaseSections(pProcess ProcessEntry);
	bool RemoveSection(pSection OldSection, pProcess ProcessEntry);
	bool AddSection(PUNICODE_STRING FileName, pProcess ProcessEntry);
	bool IsFileSectionOwner(PUNICODE_STRING FileName, ULONG Pid);
}

