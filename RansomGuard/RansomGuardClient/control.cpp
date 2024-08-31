#include <Windows.h>
#include <fltUser.h>
#include <iostream>
#include "control.h"

bool control::SendControl(int Control)
{
	HANDLE hPort = nullptr;
	WCHAR PortName[] = PORT_NAME;
	HRESULT Result = FilterConnectCommunicationPort(PortName, 0, nullptr, 0, nullptr, &hPort);
	if (FAILED(Result))
	{
		std::cout << "[*] failed to connect to RansomGuard's port" << std::endl;
		return false;
	}

	ULONG ReplyLength = 0;
	ULONG ControlBuf = Control;
	Result = FilterSendMessage(hPort, &ControlBuf, sizeof(ULONG), nullptr, 0, &ReplyLength);
	if (FAILED(Result))
	{
		std::cout << "[*] failed to send control to RansomGuard" << std::endl;
		return false;
	}

	std::cout << "[*] control sent successfully to RansomGuard" << std::endl;
	return true;
}
