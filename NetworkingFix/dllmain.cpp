#include <Windows.h>
#include <array>
#include <span>

/*
ScrapMechanic.exe.text + 4162CE: 48 8D 55 88 - lea rdx, [rbp - 78]
ScrapMechanic.exe.text + 4162D2 : FF 50 10 - call qword ptr[rax + 10]
ScrapMechanic.exe.text + 4162D5 : 80 BD 50 0A 00 00 00 - cmp byte ptr[rbp + 00000A50], 00
ScrapMechanic.exe.text + 4162DC : 0F 85 91 01 00 00 - jne ScrapMechanic.exe.text + 416473
ScrapMechanic.exe.text + 4162E2 : 8B 06 - mov eax, [rsi]
ScrapMechanic.exe.text + 4162E4 : BA 00 28 40 00 - mov edx, 00402800
ScrapMechanic.exe.text + 4162E9: 41 BC 01 00 00 00 - mov r12d, 00000001
ScrapMechanic.exe.text + 4162EF : 85 C0 - test eax, eax
ScrapMechanic.exe.text + 4162F1 : 0F 84 46 01 00 00 - je ScrapMechanic.exe.text + 41643D
ScrapMechanic.exe.text + 4162F7 : 3B F8 - cmp edi, eax
// ---------- INJECTING HERE ----------
ScrapMechanic.exe.text + 4162F9 : 0F 86 3E 01 00 00 - jbe ScrapMechanic.exe.text + 41643D
// ---------- DONE INJECTING  ----------
ScrapMechanic.exe.text + 4162FF : 80 FB 16 - cmp bl, 16
ScrapMechanic.exe.text + 416302 : 77 0D - ja ScrapMechanic.exe.text + 416311
ScrapMechanic.exe.text + 416304 : 0F B6 C3 - movzx eax, bl
ScrapMechanic.exe.text + 416307 : 0F A3 C2 - bt edx, eax
ScrapMechanic.exe.text + 41630A : 73 05 - jae ScrapMechanic.exe.text + 416311
ScrapMechanic.exe.text + 41630C : 41 8B C4 - mov eax, r12d
ScrapMechanic.exe.text + 41630F : EB 15 - jmp ScrapMechanic.exe.text + 416326
ScrapMechanic.exe.text + 416311 : 8D 43 E9 - lea eax, [rbx - 17]
ScrapMechanic.exe.text + 416314 : A8 F9 - test al, -07
ScrapMechanic.exe.text + 416316 : 75 0C - jne ScrapMechanic.exe.text + 416324
*/

// Set any version that is supported
#define _SM_VERSION_NUM 072775

#if _SM_VERSION_NUM == 072775
static constexpr std::uintptr_t offset = 0x4073DC;
static constexpr std::array<std::uint8_t, 6> originalBytes{ 0x0F, 0x86, 0x3B, 0x01, 0x00, 0x00 };
static constexpr std::array<std::uint8_t, 6> replacedBytes{ 0xE9, 0x3C, 0x01, 0x00, 0x00, 0x90 };
#elif _SM_VERSION_NUM == 071772
static constexpr std::uintptr_t offset = 0x4073BC;
static constexpr std::array<std::uint8_t, 6> originalBytes{ 0x0F, 0x86, 0x3B, 0x01, 0x00, 0x00 };
static constexpr std::array<std::uint8_t, 6> replacedBytes{ 0xE9, 0x3C, 0x01, 0x00, 0x00, 0x90 };
#elif _SM_VERSION_NUM == 066
static constexpr std::uintptr_t offset = 0x4162F9 + 0x1000;
static constexpr std::array<std::uint8_t, 6> originalBytes{ 0x0F, 0x86, 0x3E, 0x01, 0x00, 0x00 };
static constexpr std::array<std::uint8_t, 6> replacedBytes{ 0xE9, 0x3F, 0x01, 0x00, 0x00, 0x90 };
#else
#   error Unsupported game version
#endif

static void* GetFinalAddress()
{
	return reinterpret_cast<void*>(std::uintptr_t(GetModuleHandle(NULL)) + offset);
}

static bool ApplyPatch(
	void* dest,
	const std::array<std::uint8_t, 6>& orig_bytes,
	const std::array<std::uint8_t, 6>& bytes)
{
	// Failsafe to not patch game if original bytes differ
	if (memcmp(dest, orig_bytes.data(), orig_bytes.size())) return false;

	DWORD v_oldProt;
	VirtualProtect(dest, orig_bytes.size(), PAGE_EXECUTE_READWRITE, &v_oldProt);
	memcpy_s(dest, orig_bytes.size(), bytes.data(), bytes.size());
	VirtualProtect(dest, orig_bytes.size(), v_oldProt, &v_oldProt);

	return true;
}

BOOL APIENTRY DllMain(
	HMODULE hModule,
	DWORD ul_reason_for_call,
	LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
		ApplyPatch(GetFinalAddress(), originalBytes, replacedBytes);
	else if (ul_reason_for_call == DLL_PROCESS_DETACH)
		ApplyPatch(GetFinalAddress(), replacedBytes, originalBytes);

	return TRUE;
}