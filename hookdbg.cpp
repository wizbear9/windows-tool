#include <windows.h>
#include <stdio.h>

LPVOID g_pfWriteFile = NULL;
CREATE_PROCESS_DEBUG_INFO g_cpdi;
BYTE g_chINT3 = 0xCC, g_chOrgByte = 0;

// single-step 상태 관리용
BOOL g_bStepOver = FALSE;
DWORD g_dwHookThreadId = 0;

void DebugLoop(void);
void OnCreateProcessDebugEvent(LPDEBUG_EVENT pde);
DWORD OnExceptionDebugEvent(LPDEBUG_EVENT pde);

int main(int argc, char* argv[]) {
    DWORD dwPID;

    if (argc != 2) {
        printf("USAGE: hookdbg.exe <pid>\n");
        return 1;
    }

    dwPID = atoi(argv[1]);
    if (!DebugActiveProcess(dwPID)) {
        printf("DebugActiveProcess(%d) failed\n"
            "Error: %d\n", dwPID, GetLastError());
        return 1;
    }

    DebugLoop();

    return 0;
}

void DebugLoop(void) {
    DEBUG_EVENT de;
    DWORD dwContinueStatus;

    while (WaitForDebugEvent(&de, INFINITE)) {
        dwContinueStatus = DBG_CONTINUE;

        if (de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            OnCreateProcessDebugEvent(&de);
        }
        else if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            dwContinueStatus = OnExceptionDebugEvent(&de);
        }
        else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            printf("Target process exited.\n");
            break;
        }
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
    }
}

void OnCreateProcessDebugEvent(LPDEBUG_EVENT pde) {
    HMODULE hKernelBase = GetModuleHandle(L"kernelbase.dll");
    g_pfWriteFile = GetProcAddress(hKernelBase, "WriteFile");

    memcpy(&g_cpdi, &pde->u.CreateProcessInfo,
        sizeof(CREATE_PROCESS_DEBUG_INFO));
    ReadProcessMemory(g_cpdi.hProcess, g_pfWriteFile, 
        &g_chOrgByte, sizeof(BYTE), NULL);
    WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
        &g_chINT3, sizeof(BYTE), NULL);
}

DWORD OnExceptionDebugEvent(LPDEBUG_EVENT pde) {
    CONTEXT ctx;
    PBYTE lpBuffer = NULL;
    DWORD64 dwNumOfBytesToWrite, dwAddrOfBuffer;
    PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord;

    HANDLE hExceptionThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        FALSE, pde->dwThreadId);

    if (per->ExceptionCode == EXCEPTION_BREAKPOINT) {
        if (g_pfWriteFile == per->ExceptionAddress) {
            WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
                &g_chOrgByte, sizeof(BYTE), NULL);

            // rdx = lpBuffer, r8 = dwNumOfBytesToWrite
            ctx.ContextFlags = CONTEXT_FULL;
            GetThreadContext(hExceptionThread, &ctx);
            dwAddrOfBuffer = ctx.Rdx;
            dwNumOfBytesToWrite = ctx.R8;

            lpBuffer = (PBYTE)malloc(dwNumOfBytesToWrite + 1);
            memset(lpBuffer, 0, dwNumOfBytesToWrite + 1);

            ReadProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer,
                lpBuffer, dwNumOfBytesToWrite, NULL);
            printf("\n### original string: %s\n", lpBuffer);

            for (int i = 0; i < dwNumOfBytesToWrite; ++i) {
                if ('a' <= lpBuffer[i] && lpBuffer[i] <= 'z')
                    lpBuffer[i] -= 0x20;
            }

            printf("\n### converted string: %s\n", lpBuffer);
            WriteProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer,
                lpBuffer, dwNumOfBytesToWrite, NULL);

            free(lpBuffer);

            ctx.Rip = (DWORD64)g_pfWriteFile;
            ctx.EFlags |= 0x100;
            SetThreadContext(hExceptionThread, &ctx);

            // single-step lock (다른 스레드가 개입하지 못하게 고정)
            g_bStepOver = TRUE;
            g_dwHookThreadId = pde->dwThreadId;

            CloseHandle(hExceptionThread);
            return DBG_CONTINUE;
        }
        else {
            // system bp 등 내가 걸지 않은 bp는 os가 처리하도록 함
            CloseHandle(hExceptionThread);
            return DBG_CONTINUE;
        }
    }
    else if (per->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if (g_bStepOver && pde->dwThreadId == g_dwHookThreadId) {
            WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
                &g_chINT3, sizeof(BYTE), NULL);
            g_bStepOver = FALSE;
            g_dwHookThreadId = 0;

            CloseHandle(hExceptionThread);
            return DBG_CONTINUE;
        }
    }

    // 처리하지 않은 예외는 os에 넘김
    CloseHandle(hExceptionThread);
    return DBG_EXCEPTION_NOT_HANDLED;
}