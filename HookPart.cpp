#include "HookPart.hpp"




void Hook::initCMap()
{
	InjectCode tmpCode;
	tmpCode.code = { 0x48, 0xb8, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12, 0xff, 0xe0 };
	tmpCode.indexOfAddrNeedJmp = { 2 };
	cMap["Jmp"] = tmpCode;

	tmpCode.code = { 0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x89, 0x02, 0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, 0xc3 };
	tmpCode.indexOfAddrNeedJmp = { };
	cMap["CheckRemoteDebuggerPresent"] = tmpCode;

	tmpCode.code = { 0x48, 0x83, 0xfa, 0x07, 0x75, 0x1b, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x41, 0x89, 0x00, 0x48, 0x8b, 0x44, 0x24, 0x28, 0x48, 0x83, 0xf8, 0x00, 0x74, 0x4a, 0xc7, 0x00, 0x04, 0x00, 0x00, 0x00, 0xeb, 0x42, 0x48, 0x83, 0xfa, 0x1e, 0x75, 0x1d, 0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x49, 0x89, 0x00, 0x48, 0x8b, 0x44, 0x24, 0x28, 0x48, 0x83, 0xf8, 0x00, 0x74, 0x27, 0xc7, 0x00, 0x08, 0x00, 0x00, 0x00, 0xeb, 0x1f, 0x48, 0x83, 0xfa, 0x1f, 0x75, 0x21, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x41, 0x89, 0x00, 0x48, 0x8b, 0x44, 0x24, 0x28, 0x48, 0x83, 0xf8, 0x00, 0x74, 0x06, 0xc7, 0x00, 0x04, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00, 0xc3, 0x49, 0x89, 0xca, 0xb8, 0x19, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3 };
	tmpCode.indexOfAddrNeedJmp = { };
	cMap["NtQueryInformationProcess"] = tmpCode;

	tmpCode.code = { 0x48, 0x83, 0xfa, 0x11, 0x75, 0x08, 0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00, 0xc3, 0x49, 0x89, 0xca, 0xb8, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3 };
	tmpCode.indexOfAddrNeedJmp = { };
	cMap["NtSetInformationThread"] = tmpCode;

	tmpCode.code = { 0x52, 0x48, 0xb8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xff, 0xd0, 0x48, 0x83, 0xf8, 0x01, 0x75, 0x20, 0x5b, 0x8b, 0x43, 0x30, 0x83, 0xe0, 0x10, 0x74, 0x17, 0x48, 0x89, 0x53, 0x48, 0x48, 0x89, 0x53, 0x50, 0x48, 0x89, 0x53, 0x58, 0x48, 0x89, 0x53, 0x60, 0x48, 0xc7, 0xc3, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3 };
	tmpCode.indexOfAddrNeedJmp = { 3 };
	cMap["GetThreadContext"] = tmpCode;
}

void Hook::initFMap()
{
	{
		struct HookedFunc
		{
			BYTE check_return : 1;
			BYTE inline_hook : 1;
			BYTE padding : 6;
			ea_t afterCheckJmpAddr;
			ea_t addrSetHook;
			std::vector<BYTE> savedByte;
		};
	}
	HookedFunc tmpFunc(0, 0);
	fMap["CheckRemoteDebuggerPresent"] = tmpFunc;

	tmpFunc.inline_hook = 1;
	tmpFunc.check_return = 0;
	fMap["NtQueryInformationProcess"] = tmpFunc;

	tmpFunc.inline_hook = 1;
	tmpFunc.check_return = 0;
	fMap["NtSetInformationThread"] = tmpFunc;

	tmpFunc.inline_hook = 0;
	tmpFunc.check_return = 1;
	fMap["GetThreadContext"] = tmpFunc;
}


HMODULE Hook::getModule(const std::string& name)
{
	if (moduleMap.find(name) == moduleMap.end())
	{
		HMODULE x = GetModuleHandleA(name.c_str());
		moduleMap[name] = x;
	}
	return moduleMap[name];
}

ea_t Hook::memAlloc(const size_t size)//只有在之前分配的内存满了之后才开始分配新内存
{
	ea_t res = 0;
	if ((!memInUse.empty()) && (memInUse.back() % 0x10000 + size <= 0x10000))
	{
		res = memInUse.back();
		res += 0x10 - res % 0x10;
		memInUse.push_back(res + size);
		return res;
	}

	res = reinterpret_cast<ea_t>(VirtualAllocEx(data.hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	memInUse.push_back(res + size);
	return res;
}

ea_t Hook::writeCode(const std::string& funcName)
{
	auto& code = cMap[funcName].code;
	if (!cMap[funcName].indexOfAddrNeedJmp.empty())//当有留给跳转地址的空位时(just_return/check_return)
	{
		for (auto index : cMap[funcName].indexOfAddrNeedJmp)
		{
			*reinterpret_cast<ea_t*>(&code[index]) = fMap[funcName].afterCheckJmpAddr;
		}
	}
	ea_t pHookCode = memAlloc(code.size());
	msg("\n0x%llx\n", pHookCode);

	if (memWrite(reinterpret_cast<LPVOID>(pHookCode), code))
	{
		return pHookCode;
	}
	return NULL;
}
ea_t Hook::writeCode(const std::string& funcName, ea_t ea)//已有地址
{
	auto& code = cMap[funcName].code;
	if (!cMap[funcName].indexOfAddrNeedJmp.empty())//当有留给跳转地址的空位时(just_return/check_return)
	{
		for (auto index : cMap[funcName].indexOfAddrNeedJmp)
		{
			*reinterpret_cast<ea_t*>(&code[index]) = fMap[funcName].afterCheckJmpAddr;
		}
	}
	if (memWrite(reinterpret_cast<LPVOID>(ea), code))
	{
		return ea;
	}
	return NULL;
}
std::vector<BYTE> Hook::saveCode(const ea_t pCode, const size_t minSize)
{
	std::vector<BYTE> tmpCode;
	size_t size = 0;
	while (size < minSize)//取真实需要保存的大小
	{
		size += get_item_size(pCode + size);
	}
	tmpCode.resize(size);
	for (size_t i = 0; i < size; i++)
	{
		tmpCode[i] = get_wide_byte(pCode + i);
	}
	return tmpCode;
}

bool Hook::startHook(const std::string& ModuleName, const std::string& FuncName)
{
	auto& map = fMap[FuncName];
	ea_t pFunc = getFuncAddr(ModuleName, FuncName);

	if (map.inline_hook)//保存InlineHook的原始数据
	{
		map.addrSetHook = pFunc;
		map.savedByte = saveCode((pFunc), cMap["Jmp"].code.size());
		map.afterCheckJmpAddr = pFunc + cMap["Jmp"].code.size();

	}
	else//保存IATHook的数据
	{
		ea_t offsetFromNext = get_wide_dword(pFunc + 3);
		ea_t funOffset = pFunc + 7 + offsetFromNext;
		map.addrSetHook = funOffset;
		auto save = get_qword(funOffset);
		//msg("\n0x%llx\n", pFunc);
		//msg("\n0x%llx\n", funOffset);
		//msg("\n0x%llx\n", save);
		BYTE* p = reinterpret_cast<BYTE*>(&save);
		map.savedByte = { p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7] };
		map.afterCheckJmpAddr = save;
	}

	ea_t pHookCode = writeCode(FuncName);
	if (pHookCode == 0)
	{
		return false;
	}
	fMap["Jmp"].afterCheckJmpAddr = pHookCode;
	//msg("afterWrite");
	if (map.inline_hook)//TODO: inlineHook直接写jmp代码，覆盖掉的代码已经在相关的代码中了，之后可以修改成自动读取
	{
		writeCode("Jmp", pFunc);
	}
	else
	{
		std::vector<BYTE>tmpVector;
		tmpVector.resize(8);
		memcpy(tmpVector.data(), &pHookCode, 8);
		//msg("\n0x%llx\n", map.addrSetHook);

		memWrite(reinterpret_cast<LPVOID>(map.addrSetHook), tmpVector);
	}
	return true;
}

void startHookFunc()
{
	Hook hooker;
	hooker.startHook("kernel32", "CheckRemoteDebuggerPresent");
	hooker.startHook("ntdll", "NtQueryInformationProcess");
	hooker.startHook("ntdll", "NtSetInformationThread");
	hooker.startHook("kernel32", "GetThreadContext");


}
