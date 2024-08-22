#pragma once
#include <fltKernel.h>


namespace filters 
{
	FLT_PREOP_CALLBACK_STATUS
		PreWrite(
			_Inout_ PFLT_CALLBACK_DATA Data,
			_In_ PCFLT_RELATED_OBJECTS FltObjects,
			_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
		);


	FLT_POSTOP_CALLBACK_STATUS
		PostCreate(
			_Inout_ PFLT_CALLBACK_DATA Data,
			_In_ PCFLT_RELATED_OBJECTS FltObjects,
			_In_opt_ PVOID CompletionContext,
			_In_ FLT_POST_OPERATION_FLAGS Flags
		);

	FLT_PREOP_CALLBACK_STATUS
		PreCleanup(
			_Inout_ PFLT_CALLBACK_DATA Data,
			_In_ PCFLT_RELATED_OBJECTS FltObjects,
			_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
		);

	FLT_POSTOP_CALLBACK_STATUS
		PostCleanup(
			_Inout_ PFLT_CALLBACK_DATA Data,
			_In_ PCFLT_RELATED_OBJECTS FltObjects,
			_In_opt_ PVOID CompletionContext,
			_In_ FLT_POST_OPERATION_FLAGS Flags
		);

	FLT_PREOP_CALLBACK_STATUS
		PreCreate(
			_Inout_ PFLT_CALLBACK_DATA Data,
			_In_ PCFLT_RELATED_OBJECTS FltObjects,
			_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
		);

	FLT_PREOP_CALLBACK_STATUS
		PreAcquireForSectionSync(
			_Inout_ PFLT_CALLBACK_DATA Data,
			_In_ PCFLT_RELATED_OBJECTS FltObjects,
			_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
		);

	FLT_POSTOP_CALLBACK_STATUS
		PostWrite(
			_Inout_ PFLT_CALLBACK_DATA Data,
			_In_ PCFLT_RELATED_OBJECTS FltObjects,
			_In_opt_ PVOID CompletionContext,
			_In_ FLT_POST_OPERATION_FLAGS Flags
		);
	FLT_PREOP_CALLBACK_STATUS
		PreSetInformation(
			_Inout_ PFLT_CALLBACK_DATA Data,
			_In_ PCFLT_RELATED_OBJECTS FltObjects,
			_Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
	FLT_POSTOP_CALLBACK_STATUS
		PostSetInformation(
			_Inout_ PFLT_CALLBACK_DATA Data,
			_In_ PCFLT_RELATED_OBJECTS FltObjects,
			_In_opt_ PVOID CompletionContext,
			_In_ FLT_POST_OPERATION_FLAGS Flags
		);
}
