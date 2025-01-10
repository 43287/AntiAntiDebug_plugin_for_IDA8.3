#pragma once
#include "struct_h.hpp"

extern void startHookFunc();


struct InjectCode
{
	std::vector<BYTE> code;
	std::vector<BYTE> indexOfAddrNeedJmp;
};



struct HookedFunc
{
	BYTE check_return : 1;
	BYTE inline_hook : 1;
	BYTE padding : 6;
	ea_t afterCheckJmpAddr;
	ea_t addrSetHook;
	std::vector<BYTE> savedByte;
	HookedFunc(BYTE check_return_, BYTE inline_hook_)
	{
		check_return = check_return_;
		inline_hook = inline_hook_;
		padding = 0;
		afterCheckJmpAddr = 0;
		addrSetHook = 0;
		savedByte = {};
	}
	HookedFunc()
	{
		check_return = 0;
		inline_hook = 0;
		padding = 0;
		afterCheckJmpAddr = 0;
		addrSetHook = 0;
		savedByte = {};
	}
};

class Hook
{
	gData data;
	std::vector<ea_t> memInUse;
	std::unordered_map<std::string, HookedFunc> fMap;
	std::unordered_map<std::string, InjectCode> cMap;
	std::unordered_map<std::string, HMODULE> moduleMap;

private:
	void initCMap();
	void initFMap();

	HMODULE getModule(const std::string& name);
	ea_t getFuncAddr(const std::string& module, const std::string& func)
	{
		return reinterpret_cast<ea_t>(GetProcAddress(getModule(module), func.c_str()));
	}

	ea_t memAlloc(const size_t size);
	bool memWrite(LPVOID targetAddr, const std::vector<BYTE>& code)
	{
		size_t nobw;
		DWORD xold;
		VirtualProtectEx(data.hProcess, targetAddr, code.size(), PAGE_EXECUTE_READWRITE, &xold);
		BOOL res = WriteProcessMemory(data.hProcess, targetAddr, code.data(), code.size(), &nobw);
		if (!res || nobw != code.size())
		{
			VirtualFreeEx(data.hProcess, targetAddr, 0, MEM_RELEASE);
			return false;
		}
		VirtualProtectEx(data.hProcess, targetAddr, code.size(), xold, &xold);

		return true;
	}
	ea_t writeCode(const std::string& funcName);
	ea_t writeCode(const std::string& funcName, ea_t ea);
	static std::vector<BYTE> saveCode(ea_t pCode, size_t size);
public:
	Hook()
	{
		data = globalData;
		memInUse.resize(0);
		initCMap();
		initFMap();
	}
	bool startHook(const std::string& ModuleName, const std::string& FuncName);
};



