#include <Windows.h>
#include <tchar.h>

BOOL InjectDLL(DWORD dwPID, LPCTSTR szDllPath) {
	HANDLE hProcess = NULL, hThread = NULL;
	HMODULE hMod = NULL;
	LPVOID pRemoteBuf = NULL;
	DWORD dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE pThreadProc;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	if (!hProcess) {
		_tprintf(L"OpenProcess failed [%d]\n", GetLastError());
		return FALSE;
	}

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
	if (!pRemoteBuf) {
		_tprintf(L"VirtualAllocEx failed [%d]\n", GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL)) {
		_tprintf(L"WriteProcessMemory failed [%d]\n", GetLastError());
		return FALSE;
	}

	hMod = GetModuleHandle(L"kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");

	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
	if (!hThread) {
		_tprintf(L"CreateRemoteThread failed [%d]\n", GetLastError());
		return FALSE;
	}
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}

int _tmain(int argc, TCHAR* argv[]) {
	if (argc != 3) {
		_tprintf(L"Usage: %s pid dll_path\n", argv[0]);
		return 1;
	}

	if (InjectDLL((DWORD)_tstol(argv[1]), argv[2]))
		_tprintf(L"InjectDll(\"%s\") suceess\n", argv[2]);
	else
		_tprintf(L"InjectDll(\"%s\") failed\n", argv[2]);

	return 0;
}