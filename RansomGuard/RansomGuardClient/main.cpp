#include <iostream>
#include <filesystem>
#include <thread>
#include "control.h"

int main()
{
	// make sure usr restore directory exists and create it otherwise 
	const std::string UserRestoreDirectory = "C:\\RansomGuard_User_Restore";

	if (!std::filesystem::exists(UserRestoreDirectory))
		std::filesystem::create_directory(UserRestoreDirectory);

	control::SendControl(COPY_RESTORE_DIR_CONTROL);
	
}