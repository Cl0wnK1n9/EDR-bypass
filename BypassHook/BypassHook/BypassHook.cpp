// BypassHook.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>

extern "C" BOOL NtWriteProcessMemory(HANDLE  hProcess, LPVOID  lpBaseAddress, LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T* lpNumberOfBytesWritten);
int main()
{
	const char* message = "Hello World!";
	const char* overWriteMessage = "Bye World!!!";
	const char* dllPath = "NtWriteVirtualMemoryhook.dll";
	SIZE_T n;

	HMODULE hDll = LoadLibraryA(dllPath);
	if (hDll == NULL) {
		printf("[-] Fail to load DLL\n");
		return 0;
	}

	HANDLE hProcess = GetCurrentProcess();
	DWORD PID = GetCurrentProcessId();
	printf("[+] PID: %d\n", PID);
	LPVOID newMem = VirtualAlloc(NULL, strlen(message) + 1, 0x3000, 0x40);
	printf("[+] Create buffer at 0x%p\n\n", newMem);

	WriteProcessMemory(hProcess, newMem, message, strlen(message), &n);
	printf("[+] Write %zu byte(s) at 0x%p\n", n, newMem);
	printf("[+] Value: %s\n", newMem);

	printf("\n\n==== Direct Syscall ====\n");
	//bypass hooking
	NtWriteProcessMemory(hProcess, newMem, overWriteMessage, strlen(message), &n);
	printf("[+] Write %zu byte(s) at 0x%p\n", n, newMem);
	printf("[+] Value: %s\n", newMem);

	return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
