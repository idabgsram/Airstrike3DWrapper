// original source : https://gist.github.com/tame-64/1aa0132fc899a044112c53a29d21bf1b

#include <windows.h>
#include <stdio.h>
#define FORWARDED_EXPORT(exp_name, target_name) __pragma (comment (linker, "/export:" #exp_name "=" #target_name))

void init_wrapper();

FORWARDED_EXPORT(DoMessage, as3dres_main.DoMessage);

BOOL __stdcall DllMain(HMODULE hInstance, UINT_PTR ulReason, LPVOID pvReserved)
{
    switch (ulReason)
    {
    case DLL_PROCESS_ATTACH:
        init_wrapper();
        break;

    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

bool patch_offset(void* destination, const void* source, size_t size) {
    DWORD old_protection = 0;
    if (::VirtualProtect(destination, size, PAGE_READWRITE, &old_protection)) {
        ::memcpy(destination, source, size);
        DWORD throw_away = 0;
        return ::VirtualProtect(destination, size, old_protection, &throw_away);
    }
    return false;
}

bool find_offset(LONG From, LONG To)
{
    if ((To < (From + 128)) && (To > (From - 128))) {
        BYTE bpJump[2] = { 0xEB, BYTE((To - From) - 0x02) };
        return patch_offset((void*)From, bpJump, 2);
    }

    BYTE bpJump[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
    *(DWORD*)&bpJump[1] = (To - From) - 5;
    return patch_offset((void*)From, bpJump, 5);
}

void __cdecl log(const char* format_string, ...) {
    FILE* log = nullptr;
    if (0 == ::fopen_s(&log, "astrike.log", "a+"))
    {
        va_list arg_list;
        va_start(arg_list, format_string);
        if (log) ::vfprintf_s(log, format_string, arg_list);
        if (log) ::fclose(log);
        va_end(arg_list);
    }
}

void init_wrapper()
{
    find_offset(0x0040C280, (LONG)log);
}