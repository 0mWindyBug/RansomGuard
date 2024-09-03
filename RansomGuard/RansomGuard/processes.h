#pragma once
#include "Mutex.h"
#include <windef.h>
#include "files.h"

struct _Section;
typedef _Section* pSection;

typedef struct _Process
{
	ULONG Pid; 
	ULONG OriginalPid;
	ULONG ParentPid;
	PUNICODE_STRING ImagePath; 
	int FilesEncrypted;
	LIST_ENTRY* Next;
	bool Suspicious;
	bool Malicious;
	bool Terminated;
	pSection SectionsOwned;
	int SectionsCount;
	Mutex SectionsListLock;
	pDeletedFile DeletedFiles;
	int DeletedFilesCount;
	Mutex DeletedFilesLock;
} Process, * pProcess;


namespace processes
{
	bool AddProcess(pProcess NewProcess);
	bool RemoveProcess(ULONG Pid);
	bool UpdateEncryptedFiles(ULONG Pid);
	bool UpdateEncryptedFilesAsync(PUNICODE_STRING FileName);
	bool KillProcess(ULONG Pid);
	bool CheckForMaliciousSectionOwner(PUNICODE_STRING FileName);
	void DeferredRemover(PVOID StartContext);
	pProcess GetProcessEntry(ULONG ProcessId);
	void PrintProcessDetails(pProcess ProcessEntry);
	bool InitRunningProcesses();
	void ReleaseProcesses();

}


typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	// ... 
} SYSTEM_INFORMATION_CLASS;



typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


extern "C" NTSTATUS ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);

