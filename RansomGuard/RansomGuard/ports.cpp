#include "ports.h"
#include "config.h"
#include "globals.h"
#include "restore.h"

NTSTATUS ports::CreateCommunicationPort()
{
	NTSTATUS status;
	OBJECT_ATTRIBUTES ObjAttr;
	UNICODE_STRING PortName = RTL_CONSTANT_STRING(PORT_NAME);
	PSECURITY_DESCRIPTOR Sd;
	status = FltBuildDefaultSecurityDescriptor(&Sd, FLT_PORT_ALL_ACCESS);
	if (!NT_SUCCESS(status))
		return status;

	InitializeObjectAttributes(&ObjAttr, &PortName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, Sd);

	status = FltCreateCommunicationPort(gFilterHandle, &FilterPort, &ObjAttr, nullptr, ports::PortConnectCallback, ports::PortDisconnectCallback, ports::PortMessageCallback, 1);
	
	return status;
}


NTSTATUS ports::PortConnectCallback(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext, PVOID* ConnectionPortCookie)
{
	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionPortCookie);

	SendClientPort = ClientPort;

	return STATUS_SUCCESS;

}

void ports::PortDisconnectCallback(PVOID ConnectionCookie)
{
	UNREFERENCED_PARAMETER(ConnectionCookie);
	FltCloseClientPort(gFilterHandle, &SendClientPort);
	SendClientPort = nullptr;
}

NTSTATUS ports::PortMessageCallback(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnOutputBufferLength)
{
	UNREFERENCED_PARAMETER(PortCookie);
	UNREFERENCED_PARAMETER(OutputBuffer);
	UNREFERENCED_PARAMETER(OutputBufferLength);

	if (!SendClientPort)
		return STATUS_FAIL_CHECK;

	PULONG ControlCode = reinterpret_cast<PULONG>(InputBuffer);

	if (InputBuffer == nullptr || InputBufferLength < sizeof(ULONG))
		return STATUS_INVALID_PARAMETER;

	if (*ControlCode == COPY_RESTORE_DIR_CONTROL)
	{
		DbgPrint("[*] copying restore directory to a user accessible location : )\n");
		restore::CopyRestoreDirectory();
	}

	*ReturnOutputBufferLength = 0;

	return STATUS_SUCCESS;
}