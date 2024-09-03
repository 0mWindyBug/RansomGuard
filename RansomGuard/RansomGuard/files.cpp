#include "files.h"
#include "AutoLock.h"
#include "processes.h"
#include "config.h"
#include "globals.h"
#include "utils.h"


bool files::AddDeletedFile(PUNICODE_STRING FileName, PVOID Content,ULONG Size, ULONG Pid, double PreEntropy)
{
	// mutex allows acquiring recursively 
	AutoLock<Mutex> process_list_lock(ProcessesListMutex);

	pProcess ProcessEntry = processes::GetProcessEntry(Pid);
	if (!ProcessEntry)
		return false;

	AutoLock<Mutex> locker(ProcessEntry->DeletedFilesLock);


	if (ProcessEntry->DeletedFilesCount >= MAX_NUMBER_OF_FILE_DELETIONS_TO_TRACK)
		return false;

	// init new processes entry 
	pDeletedFile New = (pDeletedFile)ExAllocatePoolWithTag(NonPagedPool, sizeof(DeletedFile), TAG);
	if (!New)
		return false;

	New->Next = nullptr;
	New->PreEntropy = PreEntropy;
	New->Size = Size;
	New->Filename.Length = FileName->Length;
	New->Filename.MaximumLength = FileName->MaximumLength;
	New->Filename.Buffer = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, New->Filename.MaximumLength, TAG);
	if (!New->Filename.Buffer)
	{
		ExFreePoolWithTag(New, TAG);
		return false;
	}

	RtlCopyUnicodeString(&New->Filename, FileName);

	if (Size == 0)
	{
		ExFreePoolWithTag(New->Filename.Buffer, TAG);
		ExFreePoolWithTag(New, TAG);
		return false;
	}

	New->Content = ExAllocatePoolWithTag(NonPagedPool, Size, TAG);
	if (!New->Content)
	{
		ExFreePoolWithTag(New->Filename.Buffer, TAG);
		ExFreePoolWithTag(New, TAG);
		return false;
	}

	RtlCopyMemory(New->Content, Content, Size);


	if (!ProcessEntry->DeletedFiles)
	{
		ProcessEntry->DeletedFiles = New;
		ProcessEntry->DeletedFilesCount++;
		return true;
	}

	pDeletedFile current = ProcessEntry->DeletedFiles;
	while (current->Next != nullptr)
	{
		current = (pDeletedFile)current->Next;
	}

	current->Next = (LIST_ENTRY*)New;
	ProcessEntry->DeletedFilesCount++;
	return true;

}

// this function takes a filename and returns it's deleted content if it was deleted by the process with the same name (ignoring extension)
DeletedData files::GetDeletedFileContent(PUNICODE_STRING Filename, ULONG Pid)
{
	// mutex allows acquiring recursively 
	AutoLock<Mutex> process_list_lock(ProcessesListMutex);

	DeletedData FileData = { 0 };

	pProcess ProcessEntry = processes::GetProcessEntry(Pid);
	if (!ProcessEntry)
		return FileData;

	AutoLock<Mutex> locker(ProcessEntry->DeletedFilesLock);

	if (!ProcessEntry->DeletedFiles)
		return FileData;

	pDeletedFile current = ProcessEntry->DeletedFiles;

	UNICODE_STRING FilenameWithoutExtension = utils::RemoveFileExtension(Filename);
	UNICODE_STRING CurrentWithoutExtension = utils::RemoveFileExtension(&current->Filename);


	if (!RtlCompareUnicodeString(&CurrentWithoutExtension, &FilenameWithoutExtension, false))
	{
		FileData.Content = current->Content;
		FileData.Size = current->Size;
		FileData.PreEntropy = current->PreEntropy;
		return FileData;
	}
	while (current->Next != nullptr)
	{
		current = (pDeletedFile)current->Next;
		CurrentWithoutExtension = utils::RemoveFileExtension(&current->Filename);

		if (!RtlCompareUnicodeString(&CurrentWithoutExtension, &FilenameWithoutExtension, false))
		{
			FileData.Content = current->Content;
			FileData.Size = current->Size;
			FileData.PreEntropy = current->PreEntropy;
			return FileData;
		}
	}
	return FileData;

}


// remove deleted file entry from the deleted files list of the process
bool files::RemoveDeletedFile(pDeletedFile OldDeletedFile, pProcess ProcessEntry, bool Locked)
{
	if(!Locked)
		AutoLock<Mutex> locker(ProcessEntry->DeletedFilesLock);

	if (!ProcessEntry->DeletedFiles)
		return false;

	pDeletedFile current = ProcessEntry->DeletedFiles;
	if (current == OldDeletedFile) {
		ProcessEntry->DeletedFiles = (pDeletedFile)current->Next;
		if (current->Filename.Buffer)
			ExFreePoolWithTag(current->Filename.Buffer, TAG);
		if (current->Content)
			ExFreePoolWithTag(current->Content, TAG);

		ExFreePoolWithTag(current, TAG);
		ProcessEntry->DeletedFilesCount--;
		return true;

	}
	while (current->Next != nullptr)
	{
		pDeletedFile Last = current;
		current = (pDeletedFile)current->Next;
		if (current == OldDeletedFile)
		{
			Last->Next = current->Next;
			if (current->Filename.Buffer)
				ExFreePoolWithTag(current->Filename.Buffer, TAG);
			if (current->Content)
				ExFreePoolWithTag(current->Content, TAG);

			ExFreePoolWithTag(current, TAG);
			ProcessEntry->DeletedFilesCount--;
			return true;
		}
	}

	return false;
}

// remove deleted file entry from the deleted files list of the process
bool files::RemoveDeletedFileByName(PUNICODE_STRING Filename, ULONG Pid)
{
	// mutex allows acquiring recursively 
	AutoLock<Mutex> process_list_lock(ProcessesListMutex);


	pProcess ProcessEntry = processes::GetProcessEntry(Pid);
	if (!ProcessEntry)
		return false;

	AutoLock<Mutex> locker(ProcessEntry->DeletedFilesLock);

	if (!ProcessEntry->DeletedFiles)
		return false;

	pDeletedFile current = ProcessEntry->DeletedFiles;


	if (!RtlCompareUnicodeString(&current->Filename, Filename, false))
	{
		files::RemoveDeletedFile(current, ProcessEntry, true);
		return true;
	}
	while (current->Next != nullptr)
	{
		current = (pDeletedFile)current->Next;

		if (!RtlCompareUnicodeString(&current->Filename, Filename, false))
		{
			files::RemoveDeletedFile(current, ProcessEntry, true);
			return true;
		}
	}
	return false;
}







// release resources on unload 
void files::ReleaseDeletedFiles(pProcess ProcessEntry)
{
	AutoLock<Mutex> locker(ProcessEntry->DeletedFilesLock);
	if (ProcessEntry->DeletedFiles)
	{
		pDeletedFile current = ProcessEntry->DeletedFiles;
		pDeletedFile temp = nullptr;
		while (current != nullptr)
		{
			temp = current;
			current = (pDeletedFile)current->Next;
			files::RemoveDeletedFile(temp, ProcessEntry, true);
		}
	}
}









