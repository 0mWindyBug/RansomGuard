#pragma once
#include <fltKernel.h>



#define COPY_RESTORE_DIR_CONTROL 1
namespace ports
{
	NTSTATUS CreateCommunicationPort();
	NTSTATUS PortConnectCallback(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext, PVOID* ConnectionPortCookie);
	void PortDisconnectCallback(PVOID ConnectionCookie);
	NTSTATUS PortMessageCallback(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnOutputBufferLength);
}
