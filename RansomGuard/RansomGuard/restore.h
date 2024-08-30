#include <fltKernel.h>



namespace restore
{
	NTSTATUS CreateRestoreDirectory(PUNICODE_STRING Directory);
	NTSTATUS BackupFile(PUNICODE_STRING Name, PVOID Content, ULONG ContentSize);
	NTSTATUS RestoreFile(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject, PVOID Content, ULONG Size);
	NTSTATUS CopyRestoreDirectory();
	NTSTATUS CopyFileToUserRestoreDir(PUNICODE_STRING FilePath, PUNICODE_STRING FileName);
	void BuildRestoreNameFromPath(PUNICODE_STRING OutName, PUNICODE_STRING FilePath);
	bool IsRestoreParentDir(UNICODE_STRING ParentDir);
	
};