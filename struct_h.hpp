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















///Ч��˵����
///1.������־λ����
///==PEB-beingDebug
///==PEB-NtGlobalFlag
///==PEB-HeapFlags
///TODO:
///==������������Ƿ����ļ�����������
///==[��ʵ��]����Ƿ��е���������
///
///2.��Ҫ����Hook
///==CheckRemoteDebuggerPresent
///==NtQueryInformationProcess
///===����ProcessDebugPort,ProcessDebugObjectHandle,ProcessDebugFlags
///===����д����returnLength
///==NtSetInformationThread
///===0x11��ǰret
///==GetThreadContext
///===���Ӳ���ϵ�ǰ��ǰд���ֵ
///TODO:
///
///
///3.ʱ�ӷ�����
///==��rdtscָ���أ������沽������ʹÿ��ʱ��ֵ��ͬ
///
///
///4.����
///TODO:
///==֧���Զ���text�κ���Hook��ǿ�Ʒ���ĳ��ֵ
///
///==�����Ժ����¶ϵ�
///===VirtualProtect
///
///
///
///
///
///
///