#pragma once
#include<Windows.h>
#include <winternl.h>
//#include<winnt.h>
//#include<ntdef.h>
//#include<string>
#include <ida.hpp>
#include <idp.hpp>
#include <idd.hpp>
#include <dbg.hpp>
#include <hexrays.hpp>
#include<bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include<unordered_map>
#include<vector>
#include <random>



typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION;




//------------------------
typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PULONG ReturnLength
	);


typedef NTSTATUS(NTAPI* _NtQueryInformationThread)(
	HANDLE ThreadHandle,
	DWORD ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength,
	PULONG ReturnLength
	);





//static std::unordered_map<std::string, std::vector<BYTE>> scode;
//static std::unordered_map<std::string, BYTE> addrRef;


struct gData
{
	pid_t pid;
	HANDLE hProcess;
	bool isHooked;
};

extern gData globalData;















///效果说明：
///1.基本标志位修正
///==PEB-beingDebug
///==PEB-NtGlobalFlag
///==PEB-HeapFlags
///TODO:
///==父进程名检查是否是文件管理器启动
///==[不实现]检查是否有调试器窗口
///
///2.重要函数Hook
///==CheckRemoteDebuggerPresent
///==NtQueryInformationProcess
///===包括ProcessDebugPort,ProcessDebugObjectHandle,ProcessDebugFlags
///===主动写入了returnLength
///==NtSetInformationThread
///===0x11提前ret
///==GetThreadContext
///===检查硬件断点前提前写入空值
///TODO:
///
///
///3.时钟反调试
///==对rdtsc指令监控，汇编界面步过或步入使每次时钟值相同
///
///
///4.杂项
///TODO:
///==支持自定义text段函数Hook，强制返回某个值
///
///==主动对函数下断点
///===VirtualProtect
///
///
///
///
///
///
///