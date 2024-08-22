#include <fltKernel.h>
#include "restore.h"
#include "config.h"

NTSTATUS restore::CreateRestoreDirectory(PUNICODE_STRING directory)
{
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE directoryHandle;
    NTSTATUS status;
    InitializeObjectAttributes(&objectAttributes, directory, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(&directoryHandle,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN_IF,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);

    if (!NT_SUCCESS(status))
        return status;

    ZwClose(directoryHandle);
    return STATUS_SUCCESS;
}

NTSTATUS restore::CopyFileToUserRestoreDir(PUNICODE_STRING FilePath, PUNICODE_STRING FileName)
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    PVOID DiskContent = nullptr;
    OBJECT_ATTRIBUTES ObjAttr;
    FILE_STANDARD_INFORMATION FileInfo;
    HANDLE FileHandle;
    LARGE_INTEGER ByteOffset;
    ByteOffset.QuadPart = 0;

    InitializeObjectAttributes(&ObjAttr, FilePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);


    // read backup file 
    status = ZwCreateFile(&FileHandle, FILE_GENERIC_READ, &ObjAttr, &ioStatusBlock, nullptr,
       FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = ZwQueryInformationFile(FileHandle, &ioStatusBlock, &FileInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
    if (!NT_SUCCESS(status))
    {
        ZwClose(FileHandle);
        return status;
    }

    if (FileInfo.EndOfFile.QuadPart == 0)
    {
        ZwClose(FileHandle);
        return STATUS_ABANDONED;
    }

    DiskContent = ExAllocatePoolWithTag(NonPagedPool, FileInfo.EndOfFile.QuadPart, TAG);
    if (!DiskContent)
    {
        ZwClose(FileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwReadFile(FileHandle, nullptr, nullptr, 0, &ioStatusBlock, DiskContent, FileInfo.EndOfFile.QuadPart, &ByteOffset, nullptr);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(DiskContent,TAG);
        ZwClose(FileHandle);
        return status;
    }

    // construct destenation path 
    UNICODE_STRING TargetDirectory = RTL_CONSTANT_STRING(USER_RESTORE_DIR);
    UNICODE_STRING TargetPath;
    TargetPath.Length = 0;
    TargetPath.MaximumLength = TargetDirectory.Length + FileName->Length;
    TargetPath.Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, TargetPath.MaximumLength, TAG);
    if (!TargetPath.Buffer)
    {
        ExFreePoolWithTag(DiskContent, TAG);
        ZwClose(FileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyUnicodeString(&TargetPath, &TargetDirectory);
    RtlAppendUnicodeStringToString(&TargetPath, FileName);

    // write backup to user accessible location 
    HANDLE DestFileHandle;
    OBJECT_ATTRIBUTES DestObjAttr;
    InitializeObjectAttributes(&DestObjAttr, &TargetPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwCreateFile(&DestFileHandle, FILE_GENERIC_WRITE, &DestObjAttr, &ioStatusBlock, nullptr,
        FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);

    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(TargetPath.Buffer, TAG);
        ExFreePoolWithTag(DiskContent, TAG);
        ZwClose(FileHandle);
        return status;
    }


    ULONG BytesWritten = 0;

    status = ZwWriteFile(DestFileHandle, nullptr, nullptr, 0, &ioStatusBlock, DiskContent, FileInfo.EndOfFile.QuadPart, &ByteOffset, nullptr);

    ExFreePoolWithTag(TargetPath.Buffer, TAG);
    ExFreePoolWithTag(DiskContent, TAG);
    ZwClose(FileHandle);
    ZwClose(DestFileHandle);

    return status;

}

NTSTATUS restore::CopyRestoreDirectory()
{
    HANDLE hFile;
    IO_STATUS_BLOCK IoStatusBlock;
    OBJECT_ATTRIBUTES SourceDirObjAttr;
    UNICODE_STRING SourceDirName = RTL_CONSTANT_STRING(RESTORE_DIR);
    InitializeObjectAttributes(&SourceDirObjAttr, &SourceDirName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    NTSTATUS status = ZwOpenFile(&hFile, SYNCHRONIZE | FILE_LIST_DIRECTORY, &SourceDirObjAttr, &IoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PVOID Buffer = ExAllocatePoolWithTag(PagedPool, sizeof(FILE_FULL_DIR_INFORMATION) * 512, TAG);
    if (!Buffer)
    {
        ZwClose(hFile);
        return status;
    }

    status = ZwQueryDirectoryFile(hFile, nullptr, nullptr, 0, &IoStatusBlock, Buffer, sizeof(FILE_FULL_DIR_INFORMATION) * 512, FileFullDirectoryInformation, false, nullptr, true);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[*] failed ZwQueryDirectoryFile with 0x%x\n", status);
        ExFreePoolWithTag(Buffer, TAG);
        ZwClose(hFile);
        return status;
    }

    PFILE_FULL_DIR_INFORMATION DirInfo = reinterpret_cast<PFILE_FULL_DIR_INFORMATION>(Buffer);
    PFILE_FULL_DIR_INFORMATION Current = DirInfo;
    bool Search = true;
    int cFiles = 0;
    do
    {
        cFiles++;
        if (cFiles > 2)
        {
            UNICODE_STRING FileName;
            UNICODE_STRING FilePath;

            FileName.Buffer = Current->FileName;
            FileName.Length = Current->FileNameLength;
            FileName.MaximumLength = Current->FileNameLength ;

            FilePath.Length = 0;
            FilePath.MaximumLength = FileName.Length + SourceDirName.Length;
            FilePath.Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, FilePath.MaximumLength, TAG);
            if (!FilePath.Buffer)
            {

                ExFreePoolWithTag(Buffer, TAG);
                ZwClose(hFile);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlAppendUnicodeStringToString(&FilePath, &SourceDirName);
            RtlAppendUnicodeStringToString(&FilePath, &FileName);

            // copy the file to the user's directory 
            status = restore::CopyFileToUserRestoreDir(&FilePath, &FileName);
            if(NT_SUCCESS(status))
                DbgPrint("[*] copied %wZ to a user accessible location \n",FilePath);




            ExFreePoolWithTag(FilePath.Buffer,TAG);

        }
        if (Current->NextEntryOffset == 0)
            Search = false;
        else
            Current = (PFILE_FULL_DIR_INFORMATION)((ULONG_PTR)Current + Current->NextEntryOffset);

    } while (Search);

    ExFreePoolWithTag(Buffer, TAG);
    ZwClose(hFile);
    return STATUS_SUCCESS;

}

// this function replaces \ with _ to use as we use the file path as the name of our backups 

void restore::BuildRestoreNameFromPath(PUNICODE_STRING OutName, PUNICODE_STRING FilePath)
{

    for (USHORT i = 0; i < FilePath->Length / sizeof(WCHAR); i++)
    {
        if (FilePath->Buffer[i] == L'\\')
        {
            OutName->Buffer[i] = L'_';
        }
        else
        {
            OutName->Buffer[i] = FilePath->Buffer[i];
        }
    }
}

NTSTATUS restore::BackupFile(PUNICODE_STRING Name, PVOID Content, ULONG ContentSize)
{
    NTSTATUS status;
    UNICODE_STRING targetFilePath;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE fileHandle = NULL;
    IO_STATUS_BLOCK ioStatusBlock;

    // convert given file path to a useable backup name by replacing \ with _
    UNICODE_STRING BackupName;
    BackupName.Length = Name->Length;
    BackupName.MaximumLength = Name->MaximumLength;
    BackupName.Buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, Name->MaximumLength, TAG);
    if(!BackupName.Buffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    // construct the target file path by concatenating the backup directory path and the file name
    restore::BuildRestoreNameFromPath(&BackupName, Name);

    targetFilePath.MaximumLength = BackupName.Length  + wcslen(RESTORE_DIR) * sizeof(WCHAR);
    targetFilePath.Length = 0;
    targetFilePath.Buffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool, targetFilePath.MaximumLength, TAG);
    if (!targetFilePath.Buffer) {
        ExFreePoolWithTag(BackupName.Buffer, TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    UNICODE_STRING BackupDir = RTL_CONSTANT_STRING(RESTORE_DIR);
    RtlCopyUnicodeString(&targetFilePath, &BackupDir);

    RtlAppendUnicodeStringToString(&targetFilePath, &BackupName);

    InitializeObjectAttributes(&objectAttributes, &targetFilePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwCreateFile(&fileHandle,
        FILE_GENERIC_WRITE | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(BackupName.Buffer, TAG);
        ExFreePoolWithTag(targetFilePath.Buffer, TAG);
        return status;
    }

    status = ZwWriteFile(fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        Content,
        ContentSize,
        NULL,
        NULL);
    if (!NT_SUCCESS(status)) {
        ZwClose(fileHandle);
        ExFreePoolWithTag(BackupName.Buffer, TAG);
        ExFreePoolWithTag(targetFilePath.Buffer, TAG);
        return status;
    }

    ZwClose(fileHandle);
    ExFreePoolWithTag(BackupName.Buffer, TAG);
    ExFreePoolWithTag(targetFilePath.Buffer, TAG);

    return STATUS_SUCCESS;
}

bool restore::IsRestoreParentDir(UNICODE_STRING ParentDir)
{
    UNICODE_STRING ParentRestoreDir = RTL_CONSTANT_STRING(RESTORE_DIR_AS_PARENT_DIR);

    if (!RtlCompareUnicodeString(&ParentDir, &ParentRestoreDir, true))
        return true;

    return false;
}

NTSTATUS restore::RestoreFile(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject, PVOID Content, ULONG Length)
{
    NTSTATUS status;
    LARGE_INTEGER ByteOffset;
    ByteOffset.QuadPart = 0;
    ULONG BytesWritten = 0;
    
   status = FltWriteFile(Instance, FileObject, &ByteOffset, Length, Content, FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_PAGING | FLTFL_IO_OPERATION_SYNCHRONOUS_PAGING, &BytesWritten, nullptr, nullptr);
   if (!NT_SUCCESS(status))
       DbgPrint("[*] failed to restore file 0x%x\n", status);
   else
       DbgPrint("[*] sucessfully restored file\n");

    return status;
}

