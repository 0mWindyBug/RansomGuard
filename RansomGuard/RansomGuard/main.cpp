#include <fltKernel.h>
#include "filters.h"
#include "context.h"
#include "config.h"
#include "Mutex.h"
#include "utils.h"
#include "processes.h"
#include "restore.h"
#include "kernelcallbacks.h"
#include "ports.h"

PFLT_FILTER gFilterHandle = nullptr;
extern PFLT_PORT FilterPort = nullptr;
extern PFLT_PORT SendClientPort = nullptr;
Mutex ProcessesListMutex;
EX_RUNDOWN_REF PendingOps;


NTSTATUS 
RansomGuardInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)

{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE();



    return STATUS_SUCCESS;
}

NTSTATUS
RansomGuardUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)

{
    UNREFERENCED_PARAMETER(Flags);
    DbgPrint("[*] RansomGuard is going down...\n");
    kernel_callbacks::UnRegister();
    FltCloseCommunicationPort(FilterPort);
    FltUnregisterFilter(gFilterHandle);
    ExWaitForRundownProtectionRelease(&PendingOps);
    processes::ReleaseProcesses();
    return STATUS_SUCCESS;
}

// free internal context resources 
void RansomGuardContextCleanup(PFLT_CONTEXT Context, FLT_CONTEXT_TYPE ContextType)
{
    if (ContextType == FLT_FILE_CONTEXT)
    {
        pFileContext FileContx = (pFileContext)Context;
        if (FileContx->FileName.Buffer)
            ExFreePoolWithTag(FileContx->FileName.Buffer, TAG);

        if (FileContx->FinalComponent.Buffer)
            ExFreePoolWithTag(FileContx->FinalComponent.Buffer, TAG);
    }

    if (ContextType == FLT_STREAMHANDLE_CONTEXT)
    {
        pHandleContext HandleContx = (pHandleContext)Context;

        if (HandleContx->FileName.Buffer)
            ExFreePoolWithTag(HandleContx->FileName.Buffer, TAG);

        if (HandleContx->OriginalContent)
            ExFreePoolWithTag(HandleContx->OriginalContent, TAG);

        if (HandleContx->FinalComponent.Buffer)
            ExFreePoolWithTag(HandleContx->FinalComponent.Buffer, TAG);
    }

}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    {IRP_MJ_CREATE,NULL,filters::PreCreate, filters::PostCreate},
    {IRP_MJ_CLOSE,NULL, filters::PreCleanup, filters::PostCleanup},
    {IRP_MJ_WRITE,NULL,filters::PreWrite,nullptr},
    {IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,NULL,filters::PreAcquireForSectionSync,nullptr},
    {IRP_MJ_SET_INFORMATION,NULL,filters::PreSetInformation, filters::PostSetInformation},
    { IRP_MJ_OPERATION_END }
};



CONST FLT_CONTEXT_REGISTRATION Contexts[] = {
    { FLT_STREAMHANDLE_CONTEXT, 0, RansomGuardContextCleanup, sizeof(HandleContext),TAG},
    { FLT_FILE_CONTEXT, 0 , RansomGuardContextCleanup, sizeof(FileContext), TAG},
    { FLT_CONTEXT_END }
};



CONST FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    Contexts,                               //  Context
    Callbacks,                          //  Operation callbacks

    RansomGuardUnload,                           //  MiniFilterUnload

    RansomGuardInstanceSetup,                    //  InstanceSetup
    nullptr,            //  InstanceQueryTeardown
    nullptr,            //  InstanceTeardownStart
    nullptr,         //  InstanceTeardownComplete

    nullptr,                               //  GenerateFileName
    nullptr,                               //  GenerateDestinationFileName
    nullptr                                //  NormalizeNameComponent

};





EXTERN_C NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)

{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING RestoreDir = RTL_CONSTANT_STRING(RESTORE_DIR);
    UNICODE_STRING UserRestoreDir = RTL_CONSTANT_STRING(USER_RESTORE_DIR);

    status = restore::CreateRestoreDirectory(&RestoreDir);
    if (!NT_SUCCESS(status))
        return status;

    status = restore::CreateRestoreDirectory(&UserRestoreDir);
    if (!NT_SUCCESS(status))
        return status;


    ExReInitializeRundownProtection(&PendingOps);

    ProcessesListMutex.Init();
  
    if (!kernel_callbacks::Register())
        return STATUS_FAILED_DRIVER_ENTRY;

    processes::InitRunningProcesses();
 
    status = FltRegisterFilter(DriverObject,
        &FilterRegistration,
        &gFilterHandle);


    if (NT_SUCCESS(status)) {

        
        status = ports::CreateCommunicationPort();
        if (!NT_SUCCESS(status))
        {
            FltUnregisterFilter(gFilterHandle);
            return status;
        }
        
        status = FltStartFiltering(gFilterHandle);

        if (!NT_SUCCESS(status))
        {
            FltUnregisterFilter(gFilterHandle);
            return status;
        }
    }

    DbgPrint("[*] RansomGuard protection is active!\n");
    return status;
}

