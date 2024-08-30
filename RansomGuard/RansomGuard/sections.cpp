#include "sections.h"
#include "AutoLock.h"
#include "Mutex.h"
#include "config.h"
#include "processes.h"
#include "utils.h"
#include "globals.h"


// return true if the process created a R/W section object for the given file 
bool sections::IsFileSectionOwner(PUNICODE_STRING FileName, ULONG Pid)
{
	// mutex allows acquiring recursively 
	AutoLock<Mutex> process_list_lock(ProcessesListMutex);

	pProcess ProcessEntry = processes::GetProcessEntry(Pid);
	if (!ProcessEntry)
		return false;

	AutoLock<Mutex> locker(ProcessEntry->SectionsListLock);

	if (!ProcessEntry->SectionsOwned)
		return false;

	pSection current = ProcessEntry->SectionsOwned;

	if(!RtlCompareUnicodeString(&current->Filename, FileName, false))
		return true;
	
	while (current->Next != nullptr)
	{
		current = (pSection)current->Next;
		if (!RtlCompareUnicodeString(&current->Filename, FileName, false))
			return true;
	}

	return false;
}

// add new section entry to the section list of the process
bool sections::AddSection(PUNICODE_STRING FileName, pProcess ProcessEntry)
{
	AutoLock<Mutex> locker(ProcessEntry->SectionsListLock);

	// init new processes entry 
	pSection New = (pSection)ExAllocatePoolWithTag(NonPagedPool, sizeof(Section), TAG);
	if (!New)
		return false;

	New->Next = nullptr;
	New->Filename.Length = FileName->Length;
	New->Filename.MaximumLength = FileName->MaximumLength;
	New->Filename.Buffer = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, New->Filename.MaximumLength, TAG);
	if (!New->Filename.Buffer)
	{
		ExFreePoolWithTag(New, TAG);
		return false;
	}

	RtlCopyUnicodeString(&New->Filename, FileName);

	if (!ProcessEntry->SectionsOwned)
	{
		ProcessEntry->SectionsOwned = New;
		ProcessEntry->SectionsCount += 1;
		return true;
	}
	pSection current = ProcessEntry->SectionsOwned;
	while (current->Next != nullptr)
	{
		current = (pSection)current->Next;
	}
	current->Next = (LIST_ENTRY*)New;
	ProcessEntry->SectionsCount += 1;
	return true;

}

// remove section entry from the section list of the process
bool sections::RemoveSection(pSection OldSection, pProcess ProcessEntry)
{
	AutoLock<Mutex> locker(ProcessEntry->SectionsListLock);

	if (!ProcessEntry->SectionsOwned)
		return false;

	pSection current = ProcessEntry->SectionsOwned;
	if (current == OldSection) {
		ProcessEntry->SectionsOwned = (pSection)current->Next;
		if (current->Filename.Buffer)
			ExFreePoolWithTag(current->Filename.Buffer,TAG);

		ExFreePoolWithTag(current, TAG);
		ProcessEntry->SectionsCount -= 1;
		return true;

	}
	while (current->Next != nullptr)
	{
		pSection Last = current;
		current = (pSection)current->Next;
		if (current == OldSection)
		{
			Last->Next = current->Next;
			if (current->Filename.Buffer)
				ExFreePoolWithTag(current->Filename.Buffer, TAG);
			ExFreePoolWithTag(current, TAG);
			ProcessEntry->SectionsCount -= 1;
			return true;
		}
	}

	return false;
}

// release resources on unload 
void sections::ReleaseSections(pProcess ProcessEntry)
{
	AutoLock<Mutex> locker(ProcessEntry->SectionsListLock);
	if (ProcessEntry->SectionsOwned)
	{
		pSection current = ProcessEntry->SectionsOwned;
		pSection temp = nullptr;
		while (current != nullptr)
		{
			temp = current;
			current = (pSection)current->Next;
			sections::RemoveSection(temp, ProcessEntry);
		}
	}
}

