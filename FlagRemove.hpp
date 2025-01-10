#pragma once
#include "struct_h.hpp"

extern void startHideFlag();


class FlagRemove
{
	gData data;
	_NtQueryInformationProcess pNtQueryInformationProcess;
	PEB* peb;
	PROCESS_BASIC_INFORMATION pbi;
private:
	bool memWrite(const LPVOID taddr, const PVOID saddr, const size_t size);
	bool hideFromPebBeingDebuggedFlag();
public:
	FlagRemove();
	void startRemove();
};

