//myIdaPlugin.cpp

#include"struct_h.hpp"
#include "FlagRemove.hpp"
#include "HookPart.hpp"
#include "InstractionDetect.hpp"

long long idaapi AAD_callback(void* user_data, int notif_code, va_list va) {
	const debug_event_t* dbgEvent = va_arg(va, const debug_event_t*);
	switch (notif_code)
	{
	case dbg_process_start:
		globalData.pid = dbgEvent->pid;
		globalData.isHooked = false;
		globalData.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, globalData.pid);
		startHideFlag();
		break;
	case dbg_thread_start:
		if (!globalData.isHooked)
		{
			globalData.isHooked = true;
			startHookFunc();
		}
		break;
	case dbg_step_into:
	case dbg_step_over:
		ea_t ip = dbgEvent->ea;
		startHideFromAsm(ip - 1);
		break;
	}

	return 0;
}


plugmod_t* idaapi init(void)
{
	if (strncmp(inf.procname, "metapc", 8) != 0 || inf.filetype != f_PE)
	{
		msg("[AAD] AntiAntiDebug Only use on x86-64\n");
		return PLUGIN_SKIP;
	}
	if (!hook_to_notification_point(HT_DBG, AAD_callback, NULL))
	{
		msg("[AAD] Hook setup failed\n");
		return PLUGIN_SKIP;
	}
	msg("==========================================\n");
	msg("==========================================\n");
	msg("Anti Anti Debug Load Successfully\n");
	msg("==========================================\n");
	msg("==========================================\n");

	return PLUGIN_KEEP;
}

void idaapi term(void)
{
	unhook_from_notification_point(HT_DBG, AAD_callback, NULL);
	return;
}

bool idaapi run(size_t)
{
	//startHookFunc(tpid);
	return true;
}


static char comment[] = "I hate Anti-debugQAQ";
extern "C" plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,
  init,
  term,
  run,
  comment,
  "",
  "pRism's Helper",
  "Alt-F1"
};