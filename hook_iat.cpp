// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <wchar.h>

typedef BOOL(WINAPI* PFSETWINDOWTEXTW)(HWND hWnd, LPWSTR lpString);

FARPROC g_pOrgFunc;

BOOL WINAPI MySetWindowTextW(HWND hWnd, LPWSTR lpString) {
    const wchar_t* pNum = L"\xC601\xC77C\xC774\xC0BC\xC0AC\xC624\xC721\xCE60\xD314\xAD6C"; //L"영일이삼사오육칠팔구";
    wchar_t temp[2] = { 0, };
    int i = 0, nLen = 0;

    nLen = wcslen(lpString);
    for (i = 0; i < nLen; i++) {
        if (L'0' <= lpString[i] && lpString[i] <= L'9') {
            temp[0] = lpString[i];
            lpString[i] = pNum[_wtoi(temp)];
        }
    }

    return ((PFSETWINDOWTEXTW)g_pOrgFunc)(hWnd, lpString);
}

BOOL hook_iat(LPCSTR szDllName, LPVOID pfnOrg, LPVOID pfnNew) {
    HMODULE hMod = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS pnh = (PIMAGE_NT_HEADERS)((PBYTE)pdh + pdh->e_lfanew);
    IMAGE_DATA_DIRECTORY importDir = 
        pnh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR pidesc = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)hMod + 
        importDir.VirtualAddress);
    
    for (; pidesc->Name; pidesc++) {
        LPCSTR szLibName = (LPCSTR)((PBYTE)hMod + pidesc->Name);
        if (!_stricmp(szLibName, szDllName)) {
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((PBYTE)hMod +
                pidesc->FirstThunk);
            for (; pThunk->u1.Function; pThunk++)
            {
                if (pThunk->u1.Function == (DWORD64)pfnOrg)
                {
                    DWORD dwOldProtect;

                    // 메모리 속성을 E/R/W 로 변경
                    VirtualProtect((LPVOID)&pThunk->u1.Function,
                        8,
                        PAGE_EXECUTE_READWRITE,
                        &dwOldProtect);

                    // IAT 값을 변경
                    pThunk->u1.Function = (DWORD64)pfnNew;

                    // 메모리 속성 복원
                    VirtualProtect((LPVOID)&pThunk->u1.Function,
                        8,
                        dwOldProtect,
                        &dwOldProtect);

                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_pOrgFunc = GetProcAddress(GetModuleHandle(L"user32.dll"),
            "SetWindowTextW");
        hook_iat("user32.dll", g_pOrgFunc, (LPVOID)MySetWindowTextW);
        break;
    case DLL_PROCESS_DETACH:
        hook_iat("user32.dll", (LPVOID)MySetWindowTextW, g_pOrgFunc);
        break;
    }
    return TRUE;
}

