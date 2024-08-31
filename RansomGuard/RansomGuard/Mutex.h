#pragma once

#include <fltKernel.h>
class Mutex {
public:
	void Init();

	void Lock();
	void Unlock();

private:
	KMUTEX _mutex;
};