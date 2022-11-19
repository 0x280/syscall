#pragma once
#ifndef SYSCALL_H_
#define SYSCALL_H_

#ifdef _MSC_VER
#define SYSCALL_FORCEINLINE __forceinline
#else
#define SYSCALL_FORCEINLINE __attribute__((always_inline)) inline
#endif

#include <cstdint>
#include <vector>
namespace syscall
{
    extern "C" void __setup_syscall(std::uint32_t wSystemCall);
    extern "C" void __invoke_syscall(void);

    SYSCALL_FORCEINLINE constexpr std::uint64_t keygen() noexcept
    {
        char time[] = __TIME__;
        for (std::size_t i = 0; i < sizeof(time); i++)
        {
            time[i] = (time[i] + 125) << 2;
        }

        std::uint64_t value = 165484186ul;

        for (char c : time)
            value = static_cast<std::uint64_t>((value ^ c) * 16777619ull);
        return value;
    }
    SYSCALL_FORCEINLINE constexpr std::uint64_t strhash(const char *str) noexcept
    {
        std::uint64_t hash = keygen();
        char c = 0;

        while ((c = *str++))
            hash = ((hash << 0x5) + hash) + c;

        return hash;
    }
    SYSCALL_FORCEINLINE constexpr std::uint64_t strhash(const char *str, const std::uint32_t len) noexcept
    {
        std::uint64_t hash = keygen();
        char c = 0;

        for (std::uint32_t i = 0; i < len; i++)
        {
            c = *(str + i);
            hash = ((hash << 0x5) + hash) + c;
        }

        return hash;
    }
    SYSCALL_FORCEINLINE constexpr std::uint64_t strhash(const wchar_t *str) noexcept
    {
        std::uint64_t hash = keygen();
        wchar_t c = 0;

        while ((c = *str++))
            hash = ((hash << 0x5) + hash) + c;

        return hash;
    }
    SYSCALL_FORCEINLINE constexpr std::uint64_t strhash(const wchar_t *str, const std::uint32_t len) noexcept
    {
        std::uint64_t hash = keygen();
        wchar_t c = 0;

        for (std::uint32_t i = 0; i < len; i++)
        {
            c = *(str + i);
            hash = ((hash << 0x5) + hash) + c;
        }

        return hash;
    }

    class spinlock
    {
    private:
        bool locked;

    public:
        spinlock() : locked(false) {}
        ~spinlock() {}

        void aquire()
        {
            while (locked)
            {
            }
            locked = true;
        }
        void release()
        {
            locked = false;
        }
    };

    class spinlock_guard
    {
    private:
        spinlock &lock;

    public:
        spinlock_guard(spinlock &lock) : lock(lock)
        {
            lock.aquire();
        }
        ~spinlock_guard()
        {
            lock.release();
        }
    };

    inline spinlock mtx;
    inline std::vector<std::pair<std::uint64_t, std::uint32_t>> syscallCache{};

    SYSCALL_FORCEINLINE void setup_cache()
    {
        spinlock_guard lock(mtx);

        if (!syscallCache.empty())
            syscallCache.clear();

        // const/static vars
        const std::uint64_t ntdll_hash = strhash(L"ntdll.dll");

        // vars
        PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
        PPEB_LDR_DATA ldr = peb->Ldr;
        PVOID ntdllBase = nullptr;
        PIMAGE_DOS_HEADER dosHeaders = nullptr;
        PIMAGE_NT_HEADERS ntHeaders = nullptr;
        PIMAGE_EXPORT_DIRECTORY exportDir = nullptr;
        PDWORD functionsPtr = nullptr;
        PDWORD namesPtr = nullptr;
        PWORD namesOrdinalPtr = nullptr;

        // find ntdll.dll
        for (PLIST_ENTRY pListEntry = ldr->InMemoryOrderModuleList.Flink; pListEntry != &ldr->InMemoryOrderModuleList; pListEntry = pListEntry->Flink)
        {
            if (!pListEntry)
                continue;
            PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            if (strhash(pEntry->BaseDllName.Buffer, pEntry->BaseDllName.Length / sizeof(wchar_t)) == ntdll_hash)
            {
                ntdllBase = pEntry->DllBase;
                break;
            }
        }
        if (ntdllBase == nullptr)
            return;

        // get function export
        dosHeaders = (PIMAGE_DOS_HEADER)ntdllBase;
        if (dosHeaders->e_magic != IMAGE_DOS_SIGNATURE)
            return;

        ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)dosHeaders + dosHeaders->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
            return;

        exportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)dosHeaders + ntHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
        functionsPtr = (PDWORD)((PBYTE)dosHeaders + exportDir->AddressOfFunctions);
        namesPtr = (PDWORD)((PBYTE)dosHeaders + exportDir->AddressOfNames);
        namesOrdinalPtr = (PWORD)((PBYTE)dosHeaders + exportDir->AddressOfNameOrdinals);

        // enumerate exports
        for (std::uint16_t i = 0; i < exportDir->NumberOfNames; i++)
        {
            auto funcName = (PCHAR)((PBYTE)dosHeaders + namesPtr[i]);
            auto funcAddr = (PVOID)((PBYTE)dosHeaders + functionsPtr[namesOrdinalPtr[i]]);
            auto funcHash = strhash(funcName);

            // extract syscall, pasted from https://github.com/am0nsec/HellsGate
            for (std::uint16_t i = 0; true; i++)
            {
                if (*((PBYTE)funcAddr + i) == 0x0F && *((PBYTE)funcAddr + i + 1) == 0x05)
                    break;

                if (*((PBYTE)funcAddr + i) == 0xC3)
                    break;

                if (*((PBYTE)funcAddr + i) == 0x4C && *((PBYTE)funcAddr + i + 1) == 0x8B && *((PBYTE)funcAddr + i + 2) == 0xD1 &&
                    *((PBYTE)funcAddr + i + 3) == 0xB8 && *((PBYTE)funcAddr + i + 6) == 0x00 && *((PBYTE)funcAddr + i + 7) == 0x00)
                {
                    BYTE high = *((PBYTE)funcAddr + 5 + i);
                    BYTE low = *((PBYTE)funcAddr + 4 + i);
                    std::uint32_t syscallNr = (high << 8) | low;

                    if (syscallNr != 0)
                    {
                        // insert syscall into cache
                        syscallCache.push_back(std::make_pair(funcHash, syscallNr));
                        continue;
                    }
                }
            }
        }
    }

    template <std::uint64_t syscall_hash, class syscall_type>
    SYSCALL_FORCEINLINE syscall_type get()
    {
        std::uint32_t sc = 0;

        if (syscallCache.empty())
            setup_cache();

        spinlock_guard lg(mtx);
        for (const auto &entry : syscallCache)
        {
            if (entry.first == syscall_hash)
            {
                sc = entry.second;
                goto cleanup;
            }
        }

    cleanup:
        __setup_syscall(sc);
        return (syscall_type)__invoke_syscall;
    }
}

#define SYSCALL(name) syscall::get<syscall::strhash(#name), decltype(&name)>()

#endif