#include "Mutex.h"
#include "AutoLock.h"
#include "processes.h"
#include "config.h"
#include "utils.h"
#include "sections.h"
#include "files.h"
#include "globals.h"

pProcess ActiveProcesses = NULL;

// track process in list of active processses
bool processes::AddProcess(pProcess NewProcess)
{

	AutoLock<Mutex> locker(ProcessesListMutex);

	NTSTATUS  status;
	PEPROCESS Proc;

	// init new processes entry 
	pProcess New = (pProcess)ExAllocatePoolWithTag(NonPagedPool, sizeof(Process), TAG);
	if (!New)
		return false;

	memset(New, 0, sizeof(Process));
	New->Pid = NewProcess->Pid;
	New->OriginalPid = INVALID_PID;
	New->ParentPid = NewProcess->ParentPid;
	New->SectionsListLock.Init();
	New->DeletedFilesLock.Init();

	// init process image path 
	status = PsLookupProcessByProcessId(UlongToHandle(New->Pid), &Proc);
	if (NT_SUCCESS(status))
	{
		SeLocateProcessImageName(Proc, &New->ImagePath);
		ObDereferenceObject(Proc);
	}


	if (!ActiveProcesses)
	{
		ActiveProcesses = New;
		return true;
	}
	pProcess current = ActiveProcesses;
	while (current->Next != nullptr)
	{
		current = (pProcess)current->Next;
	}
	current->Next = (LIST_ENTRY*)New;
	return true;
}

// remove from list of active processes
bool processes::RemoveProcess(ULONG Pid)
{
	AutoLock<Mutex> locker(ProcessesListMutex);

	if (!ActiveProcesses)
		return false;

	pProcess current = ActiveProcesses;
	if (current->Pid == Pid) {
		ActiveProcesses = (pProcess)current->Next;
		if (current->ImagePath)
			ExFreePool(current->ImagePath);
		sections::ReleaseSections(current);
		files::ReleaseDeletedFiles(current);

		ExFreePoolWithTag(current, TAG);
		return true;

	}
	while (current->Next != nullptr)
	{
		pProcess Last = current;
		current = (pProcess)current->Next;
		if (current->Pid == Pid)
		{
			Last->Next = current->Next;
			if (current->ImagePath)
				ExFreePool(current->ImagePath);
			sections::ReleaseSections(current);
			files::ReleaseDeletedFiles(current);

			ExFreePoolWithTag(current, TAG);
			return true;
		}
	}

	return false;
}

// update the encryption counter of the process behind the encryption 
bool processes::UpdateEncryptedFiles(ULONG Pid)
{
	AutoLock<Mutex> locker(ProcessesListMutex);


	if (!ActiveProcesses)
		return false;


	pProcess current = ActiveProcesses;
	if (current->Pid == Pid) {
		current->Suspicious = true;
		current->FilesEncrypted += 1;

		processes::PrintProcessDetails(current);

		// act upon thresholds
		if (current->FilesEncrypted >= NUMBER_OF_FILE_ENCRYPTIONS_TO_CONDSIDER_RANSOMWARE)
		{
			current->Malicious = true;
			if (!current->Terminated)
			{
				if (processes::KillProcess(current->Pid))
					DbgPrint("[*] killed ransomware process!\n");
			}
		}
		return true;

	}
	while (current->Next != nullptr)
	{
		pProcess Last = current;
		current = (pProcess)current->Next;

		if (current->Pid == Pid)
		{
			current->Suspicious = true;
			current->FilesEncrypted += 1;

			processes::PrintProcessDetails(current);

			if (current->FilesEncrypted >= NUMBER_OF_FILE_ENCRYPTIONS_TO_CONDSIDER_RANSOMWARE)
			{
				current->Malicious = true;
				if (!current->Terminated)
				{
					if (processes::KillProcess(current->Pid))
						DbgPrint("[*] killed ransomware process!\n");
				}

			}
			return true;
		}
	}

	return false;
}

// update the encryption counter of all processes that created a R/W section object for the said file 
bool processes::UpdateEncryptedFilesAsync(PUNICODE_STRING FileName)
{
	bool Found = false;
	AutoLock<Mutex> locker(ProcessesListMutex);
	if (ActiveProcesses)
	{
		pProcess current = ActiveProcesses;
		pProcess temp = nullptr;
		while (current != nullptr)
		{
			if (sections::IsFileSectionOwner(FileName, current->Pid))
			{
				Found = true;

				current->FilesEncrypted += 1;
				current->Suspicious = true;

				processes::PrintProcessDetails(current);

				if (current->FilesEncrypted >= NUMBER_OF_FILE_ENCRYPTIONS_TO_CONDSIDER_RANSOMWARE)
				{
					current->Malicious = true;
					if (!current->Terminated)
					{
						if (processes::KillProcess(current->Pid))
							DbgPrint("[*] killed ransomware process!\n");
					}

				}


			}
			current = (pProcess)current->Next;
		}
	}

	return Found;
}




bool processes::KillProcess(ULONG Pid)
{
	ULONG IsCritical = 0;
	ULONG ReturnedLength = 0;
	HANDLE ProcessHandle;
	PEPROCESS Eprocess;
	NTSTATUS status = PsLookupProcessByProcessId(UlongToHandle(Pid), &Eprocess);
	if (!NT_SUCCESS(status))
		return false;

	status = ObOpenObjectByPointer(Eprocess, OBJ_KERNEL_HANDLE, nullptr
		, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &ProcessHandle);
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(Eprocess);
		return false;
	}


	status = ZwTerminateProcess(ProcessHandle, 0);
	if (!NT_SUCCESS(status))
	{
		ZwClose(ProcessHandle);
		ObDereferenceObject(Eprocess);
		return false;
	}

	ObDereferenceObject(Eprocess);
	ZwClose(ProcessHandle);
	return true;
}

// return true if a ransomware holds a R/W section object to the given file 
bool processes::CheckForMaliciousSectionOwner(PUNICODE_STRING FileName)
{
	AutoLock<Mutex> locker(ProcessesListMutex);
	if (ActiveProcesses)
	{
		pProcess current = ActiveProcesses;
		pProcess temp = nullptr;
		while (current != nullptr)
		{
			if (current->Malicious)
			{
				if (sections::IsFileSectionOwner(FileName, current->Pid))
				{
					return true;
				}
			}
			current = (pProcess)current->Next;
		}
	}

	return false;
}

// get process entry by process id , caller must lock the list and unlock after it's done with the process entry 
pProcess processes::GetProcessEntry(ULONG Pid)
{
	AutoLock<Mutex> locker(ProcessesListMutex);

	if (!ActiveProcesses)
		return nullptr;

	pProcess current = ActiveProcesses;

	while (current != nullptr)
	{
		if (current->Pid == Pid)
		{
			return current;
		}
		current = (pProcess)current->Next;

	}

	return nullptr;
}


// print detials on encryption 
void processes::PrintProcessDetails(pProcess ProcessEntry)
{
	if (ProcessEntry->ImagePath)
	{
		DbgPrint("[*] files encrypted by %wZ -> %d\n", ProcessEntry->ImagePath, ProcessEntry->FilesEncrypted);
	}
	else
	{
		if (ProcessEntry->Terminated)
			DbgPrint("[*] files encrypted by %d -> %d\n", ProcessEntry->OriginalPid, ProcessEntry->FilesEncrypted);
		else
			DbgPrint("[*] files encrypted by %d -> %d\n", ProcessEntry->Pid, ProcessEntry->FilesEncrypted);
	}
}

// release resources on unload 
void processes::ReleaseProcesses()
{
	AutoLock<Mutex> locker(ProcessesListMutex);
	if (ActiveProcesses)
	{
		pProcess current = ActiveProcesses;
		pProcess temp = nullptr;
		while (current != nullptr)
		{
			temp = current;
			current = (pProcess)current->Next;
			processes::RemoveProcess(temp->Pid);
		}
	}

}

// initialize list of running processes
bool processes::InitRunningProcesses()
{
	ULONG BufferSize = 0;
	NTSTATUS status;

	status = ZwQuerySystemInformation(SystemProcessInformation, nullptr, BufferSize, &BufferSize);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
		return false;

	PVOID Buffer = ExAllocatePoolWithTag(PagedPool, BufferSize + 0x1000, TAG);
	if (!Buffer)
		return false;

	status = ZwQuerySystemInformation(SystemProcessInformation, Buffer, BufferSize + 0x1000, nullptr);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(Buffer, TAG);
		return false;
	}

	PSYSTEM_PROCESS_INFORMATION RunningProcess = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(Buffer);

	do {
		ULONG Pid = HandleToUlong(RunningProcess->ProcessId);
		ULONG ParentPid = HandleToUlong(RunningProcess->InheritedFromProcessId);

		if (!processes::GetProcessEntry(Pid))
		{
			Process ProcInfo = { 0 };
			ProcInfo.FilesEncrypted = 0;
			ProcInfo.Next = nullptr;
			ProcInfo.ParentPid = ParentPid;
			ProcInfo.Suspicious = false;
			ProcInfo.Malicious = false;
			ProcInfo.Pid = Pid;
			processes::AddProcess(&ProcInfo);
		}

		if (RunningProcess->NextEntryOffset == 0)
			break;

		RunningProcess = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)RunningProcess + RunningProcess->NextEntryOffset);

	} while (true);


	ExFreePoolWithTag(Buffer, TAG);
	return true;

}

// system thread entry for deferred removal of process entries 
void processes::DeferredRemover(PVOID StartContext)
{
	ExAcquireRundownProtection(&PendingOps);
	if (StartContext)
	{
		pProcess ProcessEntry = (pProcess)StartContext;
		// fake pid in case a new process is created with the old pid 
		DbgPrint("[*] waiting two minutes to remove %d process entry\n", ProcessEntry->OriginalPid);
		utils::Wait(120000);
		processes::RemoveProcess(ProcessEntry->Pid);
	}

	ExReleaseRundownProtection(&PendingOps);

}










