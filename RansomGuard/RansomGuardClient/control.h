#pragma once

#define COPY_RESTORE_DIR_CONTROL 1 
#define PORT_NAME L"\\RansomGuardPort"


namespace control
{
	bool SendControl(int Control);
}