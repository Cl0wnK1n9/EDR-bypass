#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

#define ProcessInstrumentationCallback 40		//Use this code for intrumentation callback; non-docs;

extern "C" __forceinline PVOID callback_thunk();
//printf call NTAPI Writefile, therefore, the disable_recurs variable is needed to avoid the callback from being called again.
bool disable_recurs = false;
extern "C" unsigned int callback(unsigned __int64 r10, unsigned __int64 rax) {
	if (!disable_recurs) {
		disable_recurs = true;
		BYTE* ptr = reinterpret_cast<BYTE*>(r10);
		unsigned __int32* mark;
		do {
			mark = reinterpret_cast<unsigned __int32*>(ptr);
			ptr--;
		} while (*mark != 0xb8d18b4c);
		ptr = ptr + 5;
		CHAR buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)] = { 0 };
		PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
		pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
		pSymbol->MaxNameLen = MAX_SYM_NAME;
		DWORD64 Displacement = 0;
		BOOLEAN result = SymFromAddr(GetCurrentProcess(), r10, &Displacement, pSymbol);
		printf("Function name: %s\n", pSymbol->Name);
		printf("Syscall code: 0x%x\n", *ptr);
		printf("Function return: 0x%I64X\n", rax);
		printf("Function return address: 0x%I64X\n", r10);
		printf("***************************************************\n");
		disable_recurs = false;
	}
	return 0;
}


typedef NTSTATUS(WINAPI* NtSetInformationProcessPtr)(
	HANDLE ProcessHandle,
	UINT32 ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength
	);

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
	ULONG Version;		// version 1 = x86, 0 = x64
	ULONG Reserved;		// 0
	PVOID Callback;		// pointer to callback function
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;


int main() {
	const char* dllPath = "NtSetInformationProcess.dll";
	HMODULE hDll = LoadLibraryA(dllPath);
	if (!hDll) {
		printf("[-] Fail to load DLL");
		return 0;
	}
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION pici = { 0 };
	pici.Version = 0;
	pici.Reserved = 0;
	pici.Callback = callback_thunk;
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	NtSetInformationProcessPtr NtSetInformationProcessfn = (NtSetInformationProcessPtr)GetProcAddress(hNtdll, "NtSetInformationProcess");

	const char *message = "Hello World!"; 
	size_t n;
	HANDLE hProcess = GetCurrentProcess();
	DWORD PID = GetCurrentProcessId();

	if (!SymInitialize(GetCurrentProcess(), NULL, TRUE)) {
		printf("SymInitialize failed");
		return -1;
	}

	NtSetInformationProcessfn(hProcess, ProcessInstrumentationCallback, &pici, sizeof(pici));
	
	printf("[+] PID: %d\n", PID);
	LPVOID newMem = VirtualAlloc(NULL, strlen(message) + 1, 0x3000, 0x40);
	printf("[+] Create buffer at 0x%p\n\n", newMem);

	WriteProcessMemory(hProcess, newMem, message, strlen(message), &n);
	printf("[+] Write %zu byte(s) at 0x%p\n", n, newMem);
	printf("[+] Value: %s\n", newMem);

	return 0;
}