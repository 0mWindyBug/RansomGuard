#pragma once
#include <fltKernel.h>



class AutoContext
{
public:
	AutoContext(PFLT_CONTEXT Context) : m_context_ptr(Context) {};
	~AutoContext() { FltReleaseContext(m_context_ptr); };
private:
	PFLT_CONTEXT m_context_ptr;
};