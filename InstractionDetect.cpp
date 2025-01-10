#include "InstractionDetect.hpp"




void generate_random_dwords(DWORD& dword1, DWORD& dword2) {
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<DWORD> dis(0, 0xFFFFFFFF);

	dword1 = dis(gen);
	dword2 = dis(gen);
}
DWORD x;
DWORD y;
void startHideFromAsm(ea_t ip)
{
	if (x == 0 && y == 0)
	{
		generate_random_dwords(x, y);
	}
	qstring asmCode;
	generate_disasm_line(&asmCode, ip - 1);
	tag_remove(&asmCode);
	//msg("\n%s\n", asmCode.c_str());
	if (strstr(asmCode.c_str(), "rdtsc"))
	{
		regval_t eax;
		regval_t edx;
		//eax.ival = x;
		//edx.ival = y;
		set_reg_val("EAX", x);
		set_reg_val("EDX", y);
		//msg("\nModified reg!\n");
	}
}