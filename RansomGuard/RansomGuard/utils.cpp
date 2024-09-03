#include <fltKernel.h>
#include <windef.h>
#include "config.h"
#include <math.h>
#include "context.h"
#include "utils.h"

#define M_LOG2E 1.4426950408889634074 




static inline double log2(double n)
{
    return log(n) * M_LOG2E;
}


double utils::CalculateEntropy(PVOID Buffer, size_t Size)
{
    KFLOATING_SAVE FloatState;
    NTSTATUS status = KeSaveFloatingPointState(&FloatState);
    if (!NT_SUCCESS(status))
        return -1;

    ULONG pAlphabet[256] = {};

    size_t cbData = 0;
    for (;;)
    {
        if (cbData == Size)
        {
            break;
        }

        ASSERT(((BYTE*)Buffer)[cbData] < 256);
        pAlphabet[((BYTE*)Buffer)[cbData]]++;

        cbData++;
    }

    double dEntropy = 0.0;
    for (int i = 0; i < 256; i++)
    {
        if (pAlphabet[i] != 0)
        {

            double dTemp = (double)pAlphabet[i] / (double)cbData;
            dEntropy += (-1) * dTemp * log2(dTemp);
        }
    }

    KeRestoreFloatingPointState(&FloatState);
    return dEntropy;
}


PVOID utils::ReadFileFromDisk(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject)
{
    NTSTATUS status;
    ULONG BytesRead = 0;
    FILE_STANDARD_INFORMATION FileInfo;
    PVOID DiskContent = nullptr;
    LARGE_INTEGER ByteOffset;
    ByteOffset.QuadPart = 0;

    status = FltQueryInformationFile(Instance, FileObject, &FileInfo, sizeof(FileInfo), FileStandardInformation, NULL);
    if (!NT_SUCCESS(status))
        return nullptr;
    if (&FileObject->FileName && FileObject && FileInfo.EndOfFile.QuadPart > 0)
    {

        DiskContent = ExAllocatePoolWithTag(NonPagedPool, FileInfo.EndOfFile.QuadPart, TAG);
        if (!DiskContent)
            return nullptr;

        status = FltReadFile(Instance, FileObject, &ByteOffset, FileInfo.EndOfFile.QuadPart, DiskContent, FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_PAGING | FLTFL_IO_OPERATION_SYNCHRONOUS_PAGING, &BytesRead, NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            ExFreePoolWithTag(DiskContent, TAG);
            return nullptr;
        }

        return DiskContent;
    }

    return nullptr;
}

ULONG utils::GetFileSize(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject)
{
    FILE_STANDARD_INFORMATION FileInfo;
    NTSTATUS status = FltQueryInformationFile(Instance, FileObject, &FileInfo, sizeof(FileInfo), FileStandardInformation, NULL);
    if (!NT_SUCCESS(status))
        return 0;

    return FileInfo.EndOfFile.QuadPart;
}

double utils::CalculateChunkEntropyFromDisk(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject, PLARGE_INTEGER ByteOffset, ULONG Length)
{
    double Entropy = INVALID_ENTROPY;
    NTSTATUS status;
    ULONG BytesRead = 0;
    FILE_STANDARD_INFORMATION FileInfo;

    PVOID DiskContent = ExAllocatePoolWithTag(NonPagedPool, Length, TAG);
    if (!DiskContent)
        return INVALID_ENTROPY;

    status = FltReadFile(Instance, FileObject, ByteOffset, Length, DiskContent, FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_PAGING | FLTFL_IO_OPERATION_SYNCHRONOUS_PAGING, &BytesRead, NULL, NULL);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[*] failed to read chunk from disk 0x%x\n", status);
        ExFreePoolWithTag(DiskContent, TAG);
        return INVALID_ENTROPY;
    }

    Entropy = utils::CalculateEntropy(DiskContent, Length);

    ExFreePoolWithTag(DiskContent, TAG);

    return Entropy;

}
double utils::CalculateFileEntropy(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject, pHandleContext Context, bool InitialEntropy)
{

    double Entropy = INVALID_ENTROPY;
    NTSTATUS status;
    ULONG BytesRead = 0;
    FILE_STANDARD_INFORMATION FileInfo;
    PVOID DiskContent;
    LARGE_INTEGER ByteOffset;
    ByteOffset.QuadPart = 0;
    // get file size

    status = FltQueryInformationFile(Instance, FileObject, &FileInfo, sizeof(FileInfo), FileStandardInformation, NULL);
    if (!NT_SUCCESS(status))
    {
        return INVALID_ENTROPY;
    }
    if (&FileObject->FileName && FileObject && FileInfo.EndOfFile.QuadPart > 0)
    {

        DiskContent = ExAllocatePoolWithTag(NonPagedPool, FileInfo.EndOfFile.QuadPart, TAG);
        if (!DiskContent)
            return INVALID_ENTROPY;

        status = FltReadFile(Instance, FileObject, &ByteOffset, FileInfo.EndOfFile.QuadPart, DiskContent, FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED, &BytesRead, NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            ExFreePoolWithTag(DiskContent, TAG);
            return INVALID_ENTROPY;
        }


        Entropy = utils::CalculateEntropy(DiskContent, FileInfo.EndOfFile.QuadPart);

        if (InitialEntropy && Context)
        {
            Context->OriginalContent = DiskContent;
            Context->InitialFileSize = FileInfo.EndOfFile.QuadPart;
            Context->SavedContent = true;
        }

    }
    return Entropy;
}

ULONG GetFileSizeByName(PFLT_FILTER Filter, PFLT_INSTANCE Instance, PUNICODE_STRING FileName)
{
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE FileHandle = nullptr;
    NTSTATUS status;
    FILE_STANDARD_INFORMATION fileInfo = { 0 };



    InitializeObjectAttributes(&objAttr, FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Open the file
    status = FltCreateFile(Filter, Instance, &FileHandle, FILE_READ_DATA, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, IO_IGNORE_SHARE_ACCESS_CHECK);

    if (!NT_SUCCESS(status) || FileHandle == nullptr)
        return 0;

    PVOID Object;
    status = ObReferenceObjectByHandle(FileHandle, GENERIC_READ, *IoFileObjectType, KernelMode, &Object, NULL);
    if (!NT_SUCCESS(status))
    {
        FltClose(FileHandle);
        return 0;
    }

    PFILE_OBJECT FileObject = (PFILE_OBJECT)Object;
    FILE_STANDARD_INFORMATION FileInfo;

    status = FltQueryInformationFile(Instance, FileObject, &FileInfo, sizeof(FileInfo), FileStandardInformation, NULL);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(Object);
        FltClose(FileHandle);
        return 0;
    }

    return FileInfo.EndOfFile.QuadPart;
}

PVOID utils::ReadFileFromDiskByName(PFLT_FILTER Filter, PFLT_INSTANCE Instance, PUNICODE_STRING FileName, ULONG FileSize)
{
    ULONG BytesRead = 0;
    PVOID DiskContent = nullptr;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE FileHandle = nullptr;
    NTSTATUS status;

    LARGE_INTEGER ByteOffset;
    ByteOffset.QuadPart = 0;


    InitializeObjectAttributes(&objAttr, FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Open the file
    status = FltCreateFile(Filter, Instance, &FileHandle, FILE_READ_DATA, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, IO_IGNORE_SHARE_ACCESS_CHECK);

    if (!NT_SUCCESS(status) || FileHandle == nullptr)
        return nullptr;

    PVOID Object;
    status = ObReferenceObjectByHandle(FileHandle, GENERIC_READ, *IoFileObjectType, KernelMode, &Object, NULL);
    if (!NT_SUCCESS(status))
    {
        FltClose(FileHandle);
        return nullptr;
    }

    PFILE_OBJECT FileObject = (PFILE_OBJECT)Object;


    if (&FileObject->FileName && FileObject )
    {

        DiskContent = ExAllocatePoolWithTag(NonPagedPool, FileSize, TAG);
        if (!DiskContent)
        {
            ObDereferenceObject(Object);
            FltClose(FileHandle);
            return nullptr;
        }


        status = FltReadFile(Instance, FileObject, &ByteOffset, FileSize, DiskContent, FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED, &BytesRead, NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            ExFreePoolWithTag(DiskContent, TAG);
            ObDereferenceObject(Object);
            FltClose(FileHandle);
            return nullptr;
        }
    }
    ObDereferenceObject(Object);
    FltClose(FileHandle);
    return DiskContent;
}

double utils::CalculateFileEntropyByName(PFLT_FILTER Filter, PFLT_INSTANCE Instance, PUNICODE_STRING FileName, FLT_CONTEXT_TYPE ContextType, PFLT_CONTEXT Context)
{
    double Entropy = INVALID_ENTROPY;
    ULONG BytesRead = 0;
    PVOID DiskContent = nullptr;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE FileHandle = nullptr;
    NTSTATUS status;
    FILE_STANDARD_INFORMATION fileInfo = { 0 };
    LARGE_INTEGER ByteOffset;
    ByteOffset.QuadPart = 0;


    InitializeObjectAttributes(&objAttr, FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Open the file
    status = FltCreateFile(Filter, Instance, &FileHandle, FILE_READ_DATA, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, IO_IGNORE_SHARE_ACCESS_CHECK);

    if (!NT_SUCCESS(status) || FileHandle == nullptr)
        return INVALID_ENTROPY;

    PVOID Object;
    status = ObReferenceObjectByHandle(FileHandle, GENERIC_READ, *IoFileObjectType, KernelMode, &Object, NULL);
    if (!NT_SUCCESS(status))
    {
        FltClose(FileHandle);
        return INVALID_ENTROPY;
    }

    PFILE_OBJECT FileObject = (PFILE_OBJECT)Object;
    FILE_STANDARD_INFORMATION FileInfo;

    status = FltQueryInformationFile(Instance, FileObject, &FileInfo, sizeof(FileInfo), FileStandardInformation, NULL);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(Object);
        FltClose(FileHandle);
        return INVALID_ENTROPY;
    }

    if (&FileObject->FileName && FileObject && FileInfo.EndOfFile.QuadPart > 0)
    {

        DiskContent = ExAllocatePoolWithTag(NonPagedPool, FileInfo.EndOfFile.QuadPart, TAG);
        if (!DiskContent)
        {
            ObDereferenceObject(Object);
            FltClose(FileHandle);
            return INVALID_ENTROPY;
        }


        status = FltReadFile(Instance, FileObject, &ByteOffset, FileInfo.EndOfFile.QuadPart, DiskContent, FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED, &BytesRead, NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            ExFreePoolWithTag(DiskContent, TAG);
            ObDereferenceObject(Object);
            FltClose(FileHandle);
            return INVALID_ENTROPY;
        }

        Entropy = utils::CalculateEntropy(DiskContent, FileInfo.EndOfFile.QuadPart);
        if (Entropy == INVALID_ENTROPY)
        {
            ExFreePoolWithTag(DiskContent, TAG);
            ObDereferenceObject(Object);
            FltClose(FileHandle);
            return INVALID_ENTROPY;
        }

        if (ContextType == FLT_CREATE_CONTEXT)
        {
            pCreateCompletionContext Contx = (pCreateCompletionContext)Context;
            Contx->OriginalContent = DiskContent;
            Contx->InitialFileSize = FileInfo.EndOfFile.QuadPart;
            Contx->SavedContent = true;
        }
        if (ContextType == FLT_NO_CONTEXT)
            ExFreePoolWithTag(DiskContent, TAG);

        ObDereferenceObject(Object);
        FltClose(FileHandle);
        return Entropy;

    }

    ObDereferenceObject(Object);
    FltClose(FileHandle);
    return INVALID_ENTROPY;
}

NTSTATUS utils::WriteLog(PVOID data, ULONG dataSize) {
    UNICODE_STRING filePath;
    RtlInitUnicodeString(&filePath, EVAL_RESULTS_LOG_PATH);
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatus;

    InitializeObjectAttributes(&objectAttributes,
        &filePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = ZwOpenFile(&fileHandle,
        FILE_APPEND_DATA | SYNCHRONIZE,
        &objectAttributes,
        &ioStatus,
        FILE_SHARE_WRITE,
        FILE_SYNCHRONOUS_IO_NONALERT);

    if (!NT_SUCCESS(status)) {
        // file does not exist yet  , create it 
        if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
            ULONG createDisposition = FILE_OPEN_IF;
            ULONG fileAttributes = FILE_ATTRIBUTE_NORMAL;

            status = ZwCreateFile(&fileHandle,
                FILE_APPEND_DATA | SYNCHRONIZE,
                &objectAttributes,
                &ioStatus,
                NULL,
                fileAttributes,
                0,
                createDisposition,
                0,
                NULL,
                0);
        }

        if (!NT_SUCCESS(status)) {
            DbgPrint("[*] failed to log encryption in create 0x%x\n", status);
            return status;
        }
    }

    status = ZwWriteFile(fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        data,
        dataSize,
        NULL,
        NULL);
    if (!NT_SUCCESS(status))
        DbgPrint("[*] failed to log encryption in write 0x%x\n", status);

    ZwClose(fileHandle);

    return status;
}

void utils::Wait(LONG milliseconds)
{
    INT64 interval = milliseconds * -10000i64;
    KeDelayExecutionThread(KernelMode, FALSE, (PLARGE_INTEGER)&interval);
}


bool utils::IsFileDeleted(PFLT_FILTER Filter, PFLT_INSTANCE Instance, PUNICODE_STRING FileName)
{
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE FileHandle = nullptr;
    NTSTATUS status;

    InitializeObjectAttributes(&objAttr, FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Open the file
    status = FltCreateFile(Filter, Instance, &FileHandle, FILE_READ_DATA, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, IO_IGNORE_SHARE_ACCESS_CHECK);

    if (status == STATUS_OBJECT_NAME_NOT_FOUND)
    {
        return true;
    }
    if(NT_SUCCESS(status))
      FltClose(FileHandle);

    return false;
}

UNICODE_STRING utils::RemoveFileExtension(PUNICODE_STRING FileName)
{
    UNICODE_STRING ReturnedName;
    WCHAR* Extension = wcsrchr(FileName->Buffer, L'.');

    if (Extension) {
        ReturnedName.Buffer = FileName->Buffer;
        ReturnedName.Length = (USHORT)((Extension - FileName->Buffer) * sizeof(WCHAR));
        ReturnedName.MaximumLength = ReturnedName.Length;
    }
    else
        ReturnedName = *FileName;

    return ReturnedName;
}
