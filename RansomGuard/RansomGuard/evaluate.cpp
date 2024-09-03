#include <fltKernel.h>
#include <ntstrsafe.h>
#include <math.h>
#include "utils.h"
#include "config.h"
#include "restore.h"
#include "context.h"
#include "processes.h"
#include "sections.h"
#include "evaluate.h"




// statistical logic to determine encryption 
bool evaluate::IsEncrypted(double InitialEntropy, double FinalEntropy)
{
    if (InitialEntropy == INVALID_ENTROPY || FinalEntropy == INVALID_ENTROPY || InitialEntropy <= 0)
        return false;

    double EntropyDiff = FinalEntropy - InitialEntropy;

    // the lower the initial entropy is the higher the required diff to be considered encrypted 
    double SuspiciousDIff = (MAX_ENTROPY - InitialEntropy) * 0.83;

    if (FinalEntropy >= MIN_ENTROPY_THRESHOLD && (EntropyDiff >= SuspiciousDIff || (InitialEntropy < ENTROPY_ENCRYPTED && FinalEntropy >= ENTROPY_ENCRYPTED) ) )
        return true;

    return false;

}

void evaluate::LogEncryption(ULONG Pid, UNICODE_STRING FileName, double PreEntropy, double PostEntropy)
{
    WCHAR LogEntry[MAX_LOG_ENTRY_SIZE];
    RtlStringCbPrintfW(LogEntry, MAX_LOG_ENTRY_SIZE, L"\n[*] Encryption Detected ! (process -> %d) {File : %wZ} [ pre write entropy -> %d ]  post close entropy -> %d]\n", Pid, FileName, (int)ceil(PreEntropy * 1000), (int)ceil(PostEntropy * 1000));
    utils::WriteLog(LogEntry, wcslen(LogEntry) * sizeof(WCHAR));
}

VOID evaluate::EvaluateHandle(PFLT_DEFERRED_IO_WORKITEM FltWorkItem, PFLT_CALLBACK_DATA Data, PVOID Context)
{
    pHandleContext HandleContx = (pHandleContext)Context;

    // if delete on close was set , delete pending was set or there was a racing set disposition check if the file was deleted 
    if (HandleContx->CcbDelete || HandleContx->FcbDelete || HandleContx->NumSetInfoOps > 0)
    {

        // if the file was actually deleted add a deleted file entry in the process structure
        if (utils::IsFileDeleted(HandleContx->Filter, HandleContx->Instance, &HandleContx->FileName))
        {
            files::AddDeletedFile(&HandleContx->FileName, HandleContx->OriginalContent,HandleContx->InitialFileSize, HandleContx->RequestorPid,HandleContx->PreEntropy);

            FltReleaseContext(HandleContx);
            FltFreeDeferredIoWorkItem(FltWorkItem);
            FltCompletePendedPostOperation(Data);
            return;
        }
        
    }


    // if the file was not deleted and there was no modification made no point evaluating
    if (HandleContx->WriteOccured || HandleContx->Truncated)
    {
        HandleContx->PostEntropy = utils::CalculateFileEntropyByName(HandleContx->Filter, HandleContx->Instance, &HandleContx->FileName, FLT_NO_CONTEXT, nullptr);

        if (evaluate::IsEncrypted(HandleContx->PreEntropy, HandleContx->PostEntropy))
        {
            DbgPrint("[*] Encryption Detected\n");

            if (HandleContx->OriginalContent && HandleContx->InitialFileSize > 0)
            {
                if (NT_SUCCESS(restore::BackupFile(&HandleContx->FinalComponent, HandleContx->OriginalContent, HandleContx->InitialFileSize)))
                    DbgPrint("[*] backed up %wZ\n", HandleContx->FileName);
            }

            processes::UpdateEncryptedFiles(HandleContx->RequestorPid);

        }

    }

    FltReleaseContext(HandleContx);
    FltFreeDeferredIoWorkItem(FltWorkItem);
    FltCompletePendedPostOperation(Data);
}


