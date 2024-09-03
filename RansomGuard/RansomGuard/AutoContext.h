#pragma once
#include <fltKernel.h>



class AutoContext
{
public:
	AutoContext(PFLT_CONTEXT Context) : m_context_ptr(Context) {};
	~AutoContext()
	{if(m_context_ptr) 
		FltReleaseContext(m_context_ptr); m_context_ptr = nullptr;
	};
	void Set(PFLT_CONTEXT Context)
	{
		m_context_ptr = Context;
	}
private:
	PFLT_CONTEXT m_context_ptr;
};