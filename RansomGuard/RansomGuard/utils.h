#pragma once
#include <fltKernel.h>
#include "context.h"






namespace utils
{
	double CalculateEntropy(PVOID Buffer, size_t Size);
	double CalculateFileEntropy(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject, pHandleContext Context, bool InitialEntropy);
	double CalculateFileEntropyByName(PFLT_FILTER Filter, PFLT_INSTANCE Instance, PUNICODE_STRING FileName, FLT_CONTEXT_TYPE ContextType, PFLT_CONTEXT Context);
	double CalculateChunkEntropyFromDisk(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject, PLARGE_INTEGER ByteOffset, ULONG Length);
	NTSTATUS WriteLog(PVOID data, ULONG dataSize);
	PVOID ReadFileFromDisk(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject);
	PVOID ReadFileFromDiskByName(PFLT_FILTER Filter, PFLT_INSTANCE Instance, PUNICODE_STRING FileName, ULONG FileSize);
	ULONG GetFileSize(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject);
	bool IsFileDeleted(PFLT_FILTER Filter, PFLT_INSTANCE Instance, PUNICODE_STRING FileName);
	void Wait(LONG milliseconds);
	UNICODE_STRING RemoveFileExtension(PUNICODE_STRING FileName);

}

