#include <fltKernel.h>
#include <math.h>
#include "FilenameInfo.h"
#include "config.h"
#include "context.h"
#include "evaluate.h"
#include "restore.h"
#include "utils.h"
#include "AutoContext.h"
#include "AutoLock.h"
#include "FilenameInfo.h"
#include "processes.h"
#include "sections.h"
#include "globals.h"
#include "filters.h"

// role : for noncached paging I/O simulate and evaluate the write , for all other types of I/O calculate the initial entropy of the file in case it's the first write using the FileObject
FLT_PREOP_CALLBACK_STATUS
filters::PreWrite(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	NTSTATUS status;
	
	// not interested in writes to the paging file 
	if (FsRtlIsPagingFile(FltObjects->FileObject))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	

	// if noncached paging I/O and not to the pagefile
	if (FlagOn(Data->Iopb->IrpFlags, IRP_NOCACHE) && FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO))
	{
		pFileContext FileContx;

		// if there's a file context for the file 
		status = FltGetFileContext(FltObjects->Instance, FltObjects->FileObject, reinterpret_cast<PFLT_CONTEXT*>(&FileContx));
		if (!NT_SUCCESS(status))
			return FLT_PREOP_SUCCESS_NO_CALLBACK;

		double PreEntropy = INVALID_ENTROPY;
		double PostEntropy = INVALID_ENTROPY;
		PVOID DataCopy = nullptr;
		PVOID DataToBeWritten = nullptr;
		auto& WriteParams = Data->Iopb->Parameters.Write;
		if (WriteParams.Length == 0)
		{
			FltReleaseContext(FileContx);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}


		// retrive the data to be written 
		if (WriteParams.MdlAddress != nullptr)
		{
			DataToBeWritten = MmGetSystemAddressForMdlSafe(WriteParams.MdlAddress,NormalPagePriority | MdlMappingNoExecute);
			if (!DataToBeWritten)
			{
				FltReleaseContext(FileContx);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
		}
		// no mdl was provided so use buffer 
		else
		{
			DataToBeWritten = WriteParams.WriteBuffer;
		}
		
		DataCopy = ExAllocatePoolWithTag(NonPagedPool, WriteParams.Length, TAG);
		if (!DataCopy)
		{
			FltReleaseContext(FileContx);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}



		// read file from disk and make a copy of it 
		ULONG FileSize = utils::GetFileSize(FltObjects->Instance, FltObjects->FileObject);
		if (FileSize == 0)
		{
			FltReleaseContext(FileContx);
			ExFreePoolWithTag(DataCopy, TAG);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

		PVOID DiskContent = utils::ReadFileFromDisk(FltObjects->Instance, FltObjects->FileObject);
		if (!DiskContent)
		{
			FltReleaseContext(FileContx);
			ExFreePoolWithTag(DataCopy, TAG);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

		// make a copy of the buffer , must be done in try-except since there's a possibility it's a user buffer. 
		__try {

			RtlCopyMemory(DataCopy,
				DataToBeWritten,
				WriteParams.Length);

		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			FltReleaseContext(FileContx);
			ExFreePoolWithTag(DiskContent, TAG);
			ExFreePoolWithTag(DataCopy, TAG);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}



		// if a malicious process has a R/W section object to this file prevent the write 
		// we cant simply deny the write as the page will remain dirty which will cause the MPW to trigger again later 
		// for a *cached* write the Cc memory maps the file and copies the user data into the mapping 
		// if someone else then comes and memory maps the file the mapping will use the same physical pages backing the Cc mapping 
		// when flushing dirty pages the os builds an MDL to describe the same physical pages 
		// knowing that , modifying the buffer directly will cause everyone with the mapping to see the changes 
		// with encryption drivers, this is an issue as the intent is to only protect the data on disk 
		// in this case , we don't mind manipulating the buffer directly, otherwise the ransomware will corrupt the data 

		if (processes::CheckForMaliciousSectionOwner(&FileContx->FileName))
		{
			SIZE_T BytesToWrite = (WriteParams.Length >= FileSize) ? FileSize : WriteParams.Length;
			PVOID  OverwrittenDiskContent = (PVOID)((ULONG_PTR)DiskContent + WriteParams.ByteOffset.QuadPart);
			__try
			{
				__try
				{
					
					RtlCopyMemory(DataToBeWritten,OverwrittenDiskContent, BytesToWrite);
					DbgPrint("[*] prevented modification to %wZ by malicious process \n", FileContx->FileName);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					DbgPrint("[*] exception in attempt to prevent modification to %wZ by malicious process\n",FileContx->FileName);
				}
			}
			__finally
			{
				FltReleaseContext(FileContx);
				ExFreePoolWithTag(DiskContent, TAG);
				ExFreePoolWithTag(DataCopy, TAG);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
		}

		// simulate a write in memory 
		SIZE_T SimulatedSize = (FileSize > WriteParams.ByteOffset.QuadPart + WriteParams.Length) ? FileSize : WriteParams.ByteOffset.QuadPart + WriteParams.Length;
		PVOID SimulatedContent = ExAllocatePoolWithTag(NonPagedPool,SimulatedSize, TAG);
		if (!SimulatedContent)
		{
			FltReleaseContext(FileContx);
			ExFreePoolWithTag(DiskContent,TAG);
			ExFreePoolWithTag(DataCopy, TAG);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

		RtlCopyMemory(SimulatedContent, DiskContent, FileSize);

		RtlCopyMemory((PVOID)((ULONG_PTR)SimulatedContent + WriteParams.ByteOffset.QuadPart), DataCopy, WriteParams.Length);

		// evaluate buffers 
		PreEntropy  = utils::CalculateEntropy(DiskContent, FileSize);
		PostEntropy = utils::CalculateEntropy(SimulatedContent, FileSize);


		double EntropyDiff = PostEntropy - PreEntropy;

		DbgPrint("[*] [%wZ] pre paging write %d predicted paging write %d diff %d\n", FileContx->FileName, (int)ceil(PreEntropy * 1000), (int)ceil(PostEntropy  * 1000), (int)ceil(EntropyDiff * 1000));

		if (evaluate::IsEncrypted(PreEntropy, PostEntropy))
		{
			ULONG RequestorPid = FltGetRequestorProcessId(Data);

			if (NT_SUCCESS(restore::BackupFile(&FileContx->FileName, DiskContent, FileSize)))
				DbgPrint("[*] backed up %wZ\n", FileContx->FinalComponent);

			// synchrnous -> explicit flush 
			if (FlagOn(Data->Iopb->IrpFlags, IRP_SYNCHRONOUS_PAGING_IO) && RequestorPid != SYSTEM_PROCESS)
			{
				DbgPrint("[*] %wZ encrypted by %d\n", FileContx->FileName, RequestorPid);
				processes::UpdateEncryptedFiles(RequestorPid);
			}
			// asynchrnous -> mapped page writer write 
			else
			{
				DbgPrint("[*] %wZ encrypted by mapped page writer\n",FileContx->FileName);
				processes::UpdateEncryptedFilesAsync(&FileContx->FileName);

			}
			
		}

	

		ExFreePoolWithTag(SimulatedContent, TAG);
		ExFreePoolWithTag(DiskContent, TAG);
		ExFreePoolWithTag(DataCopy, TAG);
		FltReleaseContext(FileContx);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	}
	
	// filtering logic for all other types of I/O 
	pHandleContext HandleContx = nullptr;
	status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, reinterpret_cast<PFLT_CONTEXT*>(&HandleContx));
	if (!NT_SUCCESS(status))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	AutoContext AutoHandleContx(HandleContx);
	
	// we are only interested in new files that have been previously deleted by the same process (same name ignoring the extension) 
	// if that's the case , copy original content and size into the context's initial datapoint and mark it for evaluation (HandleContx->WriteOccured)
	// then free resources owned by the process entry , so the resources's lifetime is more accurate (file object lifetime over process lifetime) 
	// otherwise no need to mark HandleContx->WriteOccured as there's no point evaluating 
	if (HandleContx->NewFile)
	{
		
		DeletedData DeletedFileData = files::GetDeletedFileContent(&HandleContx->FileName, HandleContx->RequestorPid);
		if (DeletedFileData.Content)
		{

			// if it's the first write to this new file 
			if (!HandleContx->WriteOccured)
			{

				// copy datapoint from process entry to context 
				HandleContx->InitialFileSize = DeletedFileData.Size;
				HandleContx->OriginalContent = ExAllocatePoolWithTag(NonPagedPool, DeletedFileData.Size, TAG);

				if(!HandleContx->OriginalContent)
					return FLT_PREOP_SUCCESS_NO_CALLBACK;

				RtlCopyMemory(HandleContx->OriginalContent, DeletedFileData.Content, DeletedFileData.Size);
				
				HandleContx->PreEntropy = DeletedFileData.PreEntropy;

				HandleContx->WriteOccured = true;

				HandleContx->SavedContent = true;

				// remove deleted file from process entry 
				files::RemoveDeletedFileByName(&HandleContx->FileName, HandleContx->RequestorPid);
			}
			
		}

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}


	// we already have a datapoint in any of those cases  
	if (HandleContx->WriteOccured || HandleContx->Truncated || HandleContx->CcbDelete)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	HandleContx->WriteOccured = true;
	
	HandleContx->PreEntropy = utils::CalculateFileEntropy(FltObjects->Instance, FltObjects->FileObject, HandleContx, true);

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


// role : filter out uninteresting operations , protect our restore folder and calculate initial entropy in case file might get truncated during the create operation 
FLT_PREOP_CALLBACK_STATUS
filters::PreCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	UNREFERENCED_PARAMETER(CompletionContext);

	ULONG FileSize = 0;
	ULONG_PTR stackLow;
	ULONG_PTR stackHigh;
	NTSTATUS status;
	PFILE_OBJECT FileObject = Data->Iopb->TargetFileObject;

	// block any file-system access by malicious processes or to our restore directory 
	ProcessesListMutex.Lock();
	pProcess ProcessInfo = processes::GetProcessEntry(FltGetRequestorProcessId(Data));
	if (ProcessInfo)
	{
		if (ProcessInfo->Malicious)
		{
			ProcessesListMutex.Unlock();
			DbgPrint("[*] blocked malicious process from file-system access\n");
			Data->IoStatus.Status = STATUS_ACCESS_DENIED;
			Data->IoStatus.Information = 0;
			return FLT_PREOP_COMPLETE;
		}

	}
	ProcessesListMutex.Unlock();

	// block any usermode access to the restore directory 
	FilterFileNameInformation FileNameInfo(Data);
	if (!FileNameInfo.Get())
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	status = FileNameInfo.Parse();
	if (!NT_SUCCESS(status))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;


	
	if (restore::IsRestoreParentDir(FileNameInfo->ParentDir) && Data->RequestorMode == UserMode)
	{
		DbgPrint("[*] blocked usermode access to the restore directory\n");
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}


	//  Stack file objects are never scanned
	IoGetStackLimits(&stackLow, &stackHigh);

	if (((ULONG_PTR)FileObject > stackLow) &&
		((ULONG_PTR)FileObject < stackHigh)) 
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	//  Directory opens don't need to be scanned.
	if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	//  Skip pre-rename operations which always open a directory.
	if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	//  Skip paging files.
	if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE)) 
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	//  Skip scanning DASD opens 
	if (FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) 
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// Skip kernel mode or non write requests unless the file is opened for delete on close or delete access 
	if(Data->RequestorMode == KernelMode)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	const auto& params = Data->Iopb->Parameters.Create;

	bool DeleteOnClose = FlagOn(params.Options, FILE_DELETE_ON_CLOSE);

	bool DeleteAccess = params.SecurityContext->DesiredAccess & DELETE;

	bool WriteAccess = params.SecurityContext->DesiredAccess & FILE_WRITE_DATA;

	if (!WriteAccess && !DeleteOnClose && !DeleteAccess)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;


	ULONG Options = params.Options;
	ULONG CreateDisposition = (Options >> 24) & 0x000000ff;

	// chances are we are going to invoke the post callback , so allocate a context to pass information to it 
	pCreateCompletionContext CreateContx = (pCreateCompletionContext)FltAllocatePoolAlignedWithTag(FltObjects->Instance, NonPagedPool, sizeof(CreateCompletionContext), TAG);
	if (!CreateContx)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	memset(CreateContx, 0, sizeof(CreateCompletionContext));
	CreateContx->DeleteOnClose = DeleteOnClose;
	CreateContx->PreEntropy = INVALID_ENTROPY;

	
	// if file is marked for deletion 
	if (DeleteOnClose)
	{
		bool NotExists = utils::IsFileDeleted(FltObjects->Filter, FltObjects->Instance, &FileNameInfo->Name);
		if (!NotExists)
		{
			CreateContx->PreEntropy = utils::CalculateFileEntropyByName(FltObjects->Filter, FltObjects->Instance, &FileNameInfo->Name, FLT_CREATE_CONTEXT, CreateContx);
			if (CreateContx->PreEntropy == INVALID_ENTROPY)
			{
				FltFreePoolAlignedWithTag(FltObjects->Instance, CreateContx, TAG);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}

			CreateContx->CalculatedEntropy = true;
		}

		// no need to check for truncation if the file is marked for deletion , we have a datapoint  

		*CompletionContext = CreateContx;

		return FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}

	// if file might get truncated , check if it exists and if so capture our initial datapoint here 
	if (CreateDisposition == FILE_OVERWRITE || CreateDisposition == FILE_OVERWRITE_IF || CreateDisposition == FILE_SUPERSEDE)
	{
	
		bool NotExists = utils::IsFileDeleted(FltObjects->Filter, FltObjects->Instance, &FileNameInfo->Name);
		if (!NotExists)
		{
			CreateContx->Truncated = true;
			CreateContx->PreEntropy = utils::CalculateFileEntropyByName(FltObjects->Filter, FltObjects->Instance, &FileNameInfo->Name, FLT_CREATE_CONTEXT, CreateContx);
			if (CreateContx->PreEntropy == INVALID_ENTROPY)
			{
				FltFreePoolAlignedWithTag(FltObjects->Instance, CreateContx, TAG);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}

			CreateContx->CalculatedEntropy = true;
		}
	}

	*CompletionContext = CreateContx;


	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

// role : allocate and attach context to the file object
FLT_POSTOP_CALLBACK_STATUS
filters::PostCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)

{

	pCreateCompletionContext PreCreateInfo = (pCreateCompletionContext)CompletionContext;


	if (Flags & FLTFL_POST_OPERATION_DRAINING || !FltSupportsStreamHandleContexts(FltObjects->FileObject))
	{
		if (PreCreateInfo->SavedContent)
			ExFreePoolWithTag(PreCreateInfo->OriginalContent,TAG);

		FltFreePoolAlignedWithTag(FltObjects->Instance, CompletionContext, TAG);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	const auto& params = Data->Iopb->Parameters.Create;

	bool NewFile = (Data->IoStatus.Information == FILE_CREATED);



	// we are not interested in new files not opened for writing 
	if (NewFile && (params.SecurityContext->DesiredAccess & FILE_WRITE_DATA) == 0)
	{
		if (PreCreateInfo->SavedContent)
			ExFreePoolWithTag(PreCreateInfo->OriginalContent, TAG);

		FltFreePoolAlignedWithTag(FltObjects->Instance, CompletionContext, TAG);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}



	pHandleContext HandleContx = nullptr;
	NTSTATUS status = FltAllocateContext(FltObjects->Filter, FLT_STREAMHANDLE_CONTEXT, sizeof(HandleContext), NonPagedPool, reinterpret_cast<PFLT_CONTEXT*>(&HandleContx));
	if (!NT_SUCCESS(status))
	{
		if (PreCreateInfo->SavedContent)
			ExFreePoolWithTag(PreCreateInfo->OriginalContent, TAG);
		FltFreePoolAlignedWithTag(FltObjects->Instance, CompletionContext, TAG);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	// init context
	memset(HandleContx, 0, sizeof(HandleContext));
	HandleContx->Instance = FltObjects->Instance;
	HandleContx->Filter = FltObjects->Filter;
	HandleContx->RequestorPid  = FltGetRequestorProcessId(Data);
	HandleContx->PostEntropy = INVALID_ENTROPY;
	HandleContx->PreEntropy = INVALID_ENTROPY;
	HandleContx->SavedContent = PreCreateInfo->SavedContent;
	HandleContx->CcbDelete = PreCreateInfo->DeleteOnClose;
	HandleContx->Truncated = PreCreateInfo->Truncated;
	HandleContx->NewFile = NewFile;

	// if entropy was already calculated modify the default context (this is the case if the file was truncated or marked for delete on close 
	if (PreCreateInfo->CalculatedEntropy)
	{
		HandleContx->PreEntropy = PreCreateInfo->PreEntropy;
	}

	if (PreCreateInfo->SavedContent)
	{
		HandleContx->OriginalContent = PreCreateInfo->OriginalContent;
		HandleContx->InitialFileSize = PreCreateInfo->InitialFileSize;
	}

	// all pre create info has been moved to the handle context
	FltFreePoolAlignedWithTag(FltObjects->Instance, CompletionContext, TAG);

	FilterFileNameInformation FileNameInfo(Data);
	PFLT_FILE_NAME_INFORMATION NameInformation = FileNameInfo.Get();
	
	if (!NameInformation)
	{
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	HandleContx->FileName.Length = NameInformation->Name.Length;
	HandleContx->FileName.MaximumLength = NameInformation->Name.MaximumLength;
	if (NameInformation->Name.MaximumLength <= 0)
	{
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	HandleContx->FileName.Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, HandleContx->FileName.MaximumLength, TAG);
	if (!HandleContx->FileName.Buffer)
	{
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	

	PUNICODE_STRING FileName = &NameInformation->Name;
	if (!FileName || !FileName->Buffer)
	{
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	RtlCopyUnicodeString(&(HandleContx->FileName), FileName);

	HandleContx->FinalComponent.Length = NameInformation->FinalComponent.Length;
	HandleContx->FinalComponent.MaximumLength = NameInformation->FinalComponent.MaximumLength;
	if (NameInformation->FinalComponent.MaximumLength <= 0)
	{
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}


	HandleContx->FinalComponent.Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, HandleContx->FinalComponent.MaximumLength, TAG);

	if (!HandleContx->FinalComponent.Buffer)
	{
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	PUNICODE_STRING FinalComponent = &NameInformation->FinalComponent;
	if (!FinalComponent || !FinalComponent->Buffer)
	{
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	RtlCopyUnicodeString(&(HandleContx->FinalComponent), &NameInformation->FinalComponent);

	status = FltSetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, reinterpret_cast<PFLT_CONTEXT>(HandleContx), nullptr);
	if (!NT_SUCCESS(status))
	{
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}



	FltReleaseContext(HandleContx);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

// call post cleanup only if the a write has occured or the file is a deletion candidate
FLT_PREOP_CALLBACK_STATUS
filters::PreCleanup(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{

	pHandleContext HandleContx = nullptr;
	NTSTATUS status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, reinterpret_cast<PFLT_CONTEXT*>(&HandleContx));
	if (!NT_SUCCESS(status))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;


	// no modification was made and the file is not a deletion candidate 
	if (!HandleContx->WriteOccured && !HandleContx->CcbDelete && !HandleContx->FcbDelete && HandleContx->NumSetInfoOps == 0 && !HandleContx->Truncated)
	{
		FltReleaseContext(HandleContx);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// pass handle context pointer to post close 
	*CompletionContext = HandleContx;

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

// role : post evaluation to work item 
FLT_POSTOP_CALLBACK_STATUS
filters::PostCleanup(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)

{
	NTSTATUS status;
	FILE_STANDARD_INFORMATION FileInfo = { 0 };


	pHandleContext HandleContx = (pHandleContext)CompletionContext;
	if (!HandleContx)
		return FLT_POSTOP_FINISHED_PROCESSING;
	if (Flags & FLTFL_POST_OPERATION_DRAINING)
	{
		// release get reference from pre close 
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}


	// complete the request asynchronously at passive level 
	PFLT_DEFERRED_IO_WORKITEM EvalWorkItem = FltAllocateDeferredIoWorkItem();
	if (!EvalWorkItem)
	{
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	status = FltQueueDeferredIoWorkItem(EvalWorkItem, Data, evaluate::EvaluateHandle, DelayedWorkQueue, reinterpret_cast<PVOID>(HandleContx));
	if (!NT_SUCCESS(status))
	{
		FltFreeDeferredIoWorkItem(EvalWorkItem);
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	return FLT_POSTOP_MORE_PROCESSING_REQUIRED;
}


// role : track creation of read write seciton objects as part of our memory mapped I/O context construction 
FLT_PREOP_CALLBACK_STATUS
filters::PreAcquireForSectionSync(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	UNREFERENCED_PARAMETER(CompletionContext);

	// if a new r/w section was created 
	if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType == SyncTypeCreateSection && Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection == PAGE_READWRITE && Data->RequestorMode == UserMode)
	{
		pFileContext FileContx = nullptr;

		// allocate a file context if it does not exist yet
		NTSTATUS status = FltGetFileContext(FltObjects->Instance, FltObjects->FileObject, reinterpret_cast<PFLT_CONTEXT*>(&FileContx));
		if (!NT_SUCCESS(status))
		{

			status = FltAllocateContext(FltObjects->Filter, FLT_FILE_CONTEXT, sizeof(FileContext), NonPagedPool, reinterpret_cast<PFLT_CONTEXT*>( &FileContx));
			if (!NT_SUCCESS(status))
				return FLT_PREOP_SUCCESS_NO_CALLBACK;

			FilterFileNameInformation FileNameInfo(Data);
			if (!FileNameInfo.Get())
			{
				FltReleaseContext(FileContx);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}

			// init context
			status = FileNameInfo.Parse();
			if (!NT_SUCCESS(status))
			{
				FltReleaseContext(FileContx);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}

			FileContx->FileName.MaximumLength = FileNameInfo->Name.MaximumLength;
			FileContx->FileName.Length = FileNameInfo->Name.Length;
			if (FileNameInfo->Name.Length == 0 || !FileNameInfo->Name.Buffer)
			{
				FltReleaseContext(FileContx);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
			FileContx->FileName.Buffer = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, FileNameInfo->Name.MaximumLength, TAG);
			if (!FileContx->FileName.Buffer) {
				FltReleaseContext(FileContx);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
			RtlCopyUnicodeString(&FileContx->FileName, &FileNameInfo->Name);


			FileContx->FinalComponent.MaximumLength = FileNameInfo->FinalComponent.MaximumLength;
			FileContx->FinalComponent.Length = FileNameInfo->FinalComponent.Length;

			if (FileNameInfo->FinalComponent.Length == 0 || !FileNameInfo->FinalComponent.Buffer)
			{
				FltReleaseContext(FileContx);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
			FileContx->FinalComponent.Buffer = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, FileNameInfo->FinalComponent.MaximumLength, TAG);
			if (!FileContx->FinalComponent.Buffer) {
				FltReleaseContext(FileContx);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
			RtlCopyUnicodeString(&FileContx->FinalComponent, &FileNameInfo->FinalComponent);

			// attach context to file
			status = FltSetFileContext(FltObjects->Instance, FltObjects->FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, FileContx, nullptr);
			if (!NT_SUCCESS(status))
			{
				FltReleaseContext(FileContx);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
			
			DbgPrint("[*] R/W section is created for %wZ\n", FileContx->FinalComponent);
		}

		// add section entry in process structure 
		AutoLock<Mutex>process_list_lock(ProcessesListMutex);
		pProcess ProcessEntry = processes::GetProcessEntry(FltGetRequestorProcessId(Data));
		if (!ProcessEntry)
		{
			FltReleaseContext(FileContx);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

		sections::AddSection(&FileContx->FileName, ProcessEntry);

		FltReleaseContext(FileContx);
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


// track disposition requests and delete related operations 
FLT_PREOP_CALLBACK_STATUS
filters::PreSetInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {

	case FileDispositionInformation:
	case FileDispositionInformationEx:


		pHandleContext HandleContx = nullptr;
		NTSTATUS status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, reinterpret_cast<PFLT_CONTEXT*>(&HandleContx));
		if (!NT_SUCCESS(status))
			return FLT_PREOP_SUCCESS_NO_CALLBACK;


		// a disposition request is in progress 
		HandleContx->NumSetInfoOps++;


		// there's already a racing request in progress, we cant tell which request will make it first to the file-system . 
		// in such case , NumSetInfoOps will not be 0 on cleanup , one of the conditions to check for deletion 
		if (HandleContx->NumSetInfoOps > 1)
		{
			FltReleaseContext(HandleContx);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

		// capture initial datapoint if we don't already have one 
		if (!HandleContx->SavedContent)
		{
			HandleContx->PreEntropy = utils::CalculateFileEntropy(FltObjects->Instance, FltObjects->FileObject, HandleContx, true);
		}

		*CompletionContext = HandleContx;

		return FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


// if request was successful , update context based on the disposition structure passed 
FLT_POSTOP_CALLBACK_STATUS
filters::PostSetInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)

{

	pHandleContext HandleContx = (pHandleContext)CompletionContext;
	if (!HandleContx)
		return FLT_POSTOP_FINISHED_PROCESSING;

	if (Flags & FLTFL_POST_OPERATION_DRAINING)
	{
		FltReleaseContext(HandleContx);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (NT_SUCCESS(Data->IoStatus.Status)) {


		if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformationEx) {

			ULONG flags = ((PFILE_DISPOSITION_INFORMATION_EX)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->Flags;

			if (FlagOn(flags, FILE_DISPOSITION_ON_CLOSE)) {

				HandleContx->CcbDelete = BooleanFlagOn(flags, FILE_DISPOSITION_DELETE);

			}
			else {
				HandleContx->FcbDelete = BooleanFlagOn(flags, FILE_DISPOSITION_DELETE);


			}

		}
		else {
			HandleContx->FcbDelete = ((PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->DeleteFile;

		}
	}

	HandleContx->NumSetInfoOps--;

	FltReleaseContext(HandleContx);

	return FLT_POSTOP_FINISHED_PROCESSING;
}



