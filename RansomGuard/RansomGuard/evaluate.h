#pragma once
#include <fltKernel.h>



namespace evaluate
{
	VOID EvaluateHandle(PFLT_DEFERRED_IO_WORKITEM FltWorkItem, PFLT_CALLBACK_DATA Data, PVOID Context);
	bool IsEncrypted(double InitialEntropy, double FinalEntropy);
	void LogEncryption(ULONG Pid, UNICODE_STRING FileName, double PreEntropy, double PostEntropy);

}