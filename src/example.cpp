#include <syscall.hpp>

#include <Windows.h>
#include <ntstatus.h>
#include <iostream>

typedef HKL(WINAPI *NtUserGetKeyboardLayout)(DWORD idThread);
typedef BOOL(WINAPI *NtUserGetKeyboardLayoutName)(LPWSTR pwszKLID);

int main()
{
    LoadLibraryA("user32.dll");

    NTSTATUS status = STATUS_SUCCESS;

    PVOID base_address = nullptr;
    SIZE_T region_size = 0x1000;
    status = SYSCALL(NtAllocateVirtualMemory)(
        NtCurrentProcess(),
        &base_address,
        0,
        &region_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        std::cout << "[-] Failed to allocate memory: " << std::hex << status << std::endl;
        return 1;
    }
    std::cout << "[+] Allocated memory at: 0x" << std::hex << base_address << std::endl;

    status = SYSCALL(NtWriteVirtualMemory)(
        NtCurrentProcess(),
        base_address,
        "Hello, world!",
        14,
        nullptr);
    if (!NT_SUCCESS(status))
    {
        std::cout << "[-] Failed to write memory: " << std::hex << status << std::endl;
        return 1;
    }
    std::cout << "[+] Wrote memory" << std::endl;

    char *allocPointer = reinterpret_cast<char *>(base_address);
    std::cout << "[+] Read memory: " << allocPointer << std::endl;

    status = SYSCALL(NtFreeVirtualMemory)(
        NtCurrentProcess(),
        &base_address,
        &region_size,
        MEM_RELEASE);
    if (!NT_SUCCESS(status))
    {
        std::cout << "[-] Failed to free memory: " << std::hex << status << std::endl;
        return 1;
    }
    std::cout << "[+] Freed memory" << std::endl;

    auto ntUserGetKeyboardLayout = syscall::__get_syscall<syscall::__hash_str("NtUserGetKeyboardLayout"), NtUserGetKeyboardLayout>();

    printf("NtUserGetKeyboardLayout: 0x%p\n", ntUserGetKeyboardLayout);

    HKL hkl = ntUserGetKeyboardLayout(0);
    printf("NtUserGetKeyboardLayout(0): 0x%p\n", hkl);
}
