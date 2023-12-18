# syscall - msvc-compatible inline dynamic x64 syscall invocation for windows

## What?

This library provides functionality to dynamically parse and invoke x64 windows syscalls (specifically windows nt syscalls) using a simple macro.

## How?

To avoid using any common windows api like [GetModuleHandle](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea) or [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) the [PEB_LDR_DATA](http://undocumented.ntinternals.net/index.html?page=UserMode%2FStructures%2FPEB_LDR_DATA.html) in the [Process Environment Block (PEB)](https://en.wikipedia.org/wiki/Process_Environment_Block) is manually walked to get the base address of ```ntdll.dll``` to parse the exports table of ntdll.dll and parse all possible syscall indexes for Nt apis and store them in a map.
Using cpp templates and macros a higher level function and macro is provided to provide a easy to use interface for invoking a specific Nt-Api/Syscall using a small asm stub.

## Why?

The already existing similar project [inline_syscall](https://github.com/JustasMasiulis/inline_syscall) is great but only works on clang, so I've hacked this together by basically combining aspects of both [inline_syscall](https://github.com/JustasMasiulis/inline_syscall) and [Hells Gate](https://github.com/vxunderground/VXUG-Papers/tree/main/Hells%20Gate).

## Limits

Due to way the syscall gets [invoked](src/syscall.asm) this project **does not support multithreading** without the possibility of undefined behaviour.

## [Example](src/example.cpp)

```cpp
NTSTATUS status = SYSCALL(NtClose)((HANDLE)-1);
```
