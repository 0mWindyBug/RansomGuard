#pragma once

namespace kernel_callbacks
{
	bool Register();
	void UnRegister();
	VOID RansomGuardProcessCallback(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create);

}