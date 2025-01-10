#include "FlagRemove.hpp"

bool FlagRemove::memWrite(const LPVOID taddr, const PVOID saddr, const size_t size)
{
	size_t written;
	const bool ans = WriteProcessMemory(data.hProcess, taddr, saddr, size, &written);
	return ans && (written == size);
}

FlagRemove::FlagRemove()
{
	data = globalData;
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll)
		return;
	pNtQueryInformationProcess = reinterpret_cast<_NtQueryInformationProcess>(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
	if (!pNtQueryInformationProcess)
		return;

	DWORD returnLength;

	const NTSTATUS status = pNtQueryInformationProcess(
		data.hProcess,
		0,
		&pbi,
		sizeof(pbi),
		&returnLength
	);
	if (status != 0)
		return;
	peb = pbi.PebBaseAddress;
}

void FlagRemove::startRemove()
{
	hideFromPebBeingDebuggedFlag();
}

bool FlagRemove::hideFromPebBeingDebuggedFlag()
{
	BYTE BeingDebugged = 0;
	if (!memWrite(&peb->BeingDebugged, &BeingDebugged, sizeof(BeingDebugged)))
		return false;
	return true;
}

void startHideFlag()
{
	FlagRemove eflag;
	eflag.startRemove();

}