#include <fltKernel.h>
#include "processes.h"
#include "config.h"
#include "kernelcallbacks.h"

VOID kernel_callbacks::RansomGuardProcessCallback(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
	// if termination just release the process structure 
	if (!Create)
	{
		// if the process has created several R/W sections defer removal to a later time so the entry persists until a potential mapped page writer write
		// we need this to evaluate and block future mapped page writer writes and block them in case a process entry marked as malicious owns a section to it 
		pProcess ProcessEntry = processes::GetProcessEntry(HandleToUlong(ProcessId));
		if (!ProcessEntry)
			return;

		ProcessEntry->Terminated = true;

		if (ProcessEntry->SectionsCount >= NUMBER_OF_SECTIONS_TO_DEFER_REMOVAL)
		{
			ProcessEntry->OriginalPid = ProcessEntry->Pid;
			ProcessEntry->Pid = INVALID_PID;
			NTSTATUS status;
			HANDLE ThreadHandle;
			status = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, processes::DeferredRemover, ProcessEntry);
			if (!NT_SUCCESS(status))
			{
				DbgPrint("[*] could not defer removal to system thread : ( \n");
				processes::RemoveProcess(HandleToUlong(ProcessId));
			}
		}
		else
		{
			processes::RemoveProcess(HandleToUlong(ProcessId));
		}
	}
	else
	{
		Process ProcessInfo = { 0 };
		ProcessInfo.FilesEncrypted = 0;
		ProcessInfo.Pid = HandleToUlong(ProcessId);
		ProcessInfo.ParentPid = HandleToUlong(ParentId);
		ProcessInfo.Suspicious = false;
		ProcessInfo.Malicious = false;
		processes::AddProcess(&ProcessInfo);
	}

}

bool kernel_callbacks::Register()
{
	NTSTATUS status = PsSetCreateProcessNotifyRoutine(kernel_callbacks::RansomGuardProcessCallback, FALSE);
	if (!NT_SUCCESS(status))
		return false;
	return true;
}

void kernel_callbacks::UnRegister()
{
	PsSetCreateProcessNotifyRoutine(kernel_callbacks::RansomGuardProcessCallback, TRUE);
}