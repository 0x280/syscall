#pragma once

#ifdef _MSC_VER
#define SYSCALL_FORCEINLINE __forceinline
#else
#define SYSCALL_FORCEINLINE inline __attribute__((always_inline))
#endif

#include <cstdint>
#include <cstddef>
#include <map>
#include <cassert>

#include <ntos.h>

namespace syscall
{
    extern "C" void __setup_syscall(std::uint32_t dwSyscallIndex);
    extern "C" void __invoke_syscall(void);

    using key_t = std::uint64_t;
    using syscall_index_t = std::uint32_t;

    /**
     * @brief Generates a random uint64_t key at compile time.
     *
     * @return constexpr std::uint64_t
     */
    SYSCALL_FORCEINLINE constexpr key_t __generate_key() noexcept
    {
        char time[] = __TIME__;

        for (std::size_t i = 0; i < sizeof(time); i++)
        {
            time[i] = (time[i] + 125) << 2;
        }

        const std::uint64_t seed = 0xdeadbeef;

        std::uint64_t key = seed;
        for (std::size_t i = 0; i < sizeof(time); i++)
        {
            key = (key ^ time[i]) * seed;
        }

        return key;
    }

    /**
     * @brief Hashes a string at compile time.
     *
     * @param str
     * @return constexpr std::uint64_t
     */
    SYSCALL_FORCEINLINE constexpr key_t __hash_str(const char *str) noexcept
    {
        std::uint64_t hash = __generate_key();

        char c = 0;
        while ((c = *str++))
        {
            hash = hash ^ (c << (c % 8));
        }

        return hash;
    }

    /**
     * @brief Hashes a string at compile time.
     *
     * @param str
     * @param len
     * @return constexpr std::uint64_t
     */
    SYSCALL_FORCEINLINE constexpr key_t __hash_str(const char *str, const std::size_t len) noexcept
    {
        std::uint64_t hash = __generate_key();

        for (std::size_t i = 0; i < len; i++)
        {
            hash = hash ^ (str[i] << (str[i] % 8));
        }

        return hash;
    }

    /**
     * @brief Hashes a string at compile time. Non-ASCII characters will be ignored.
     *
     * @param str
     * @return constexpr std::uint64_t
     */
    SYSCALL_FORCEINLINE constexpr key_t __hash_str(const wchar_t *str) noexcept
    {
        std::uint64_t hash = __generate_key();

        wchar_t c = 0;
        while ((c = *str++))
        {
            if (c > 0x7f)
                continue;

            hash = hash ^ (c << (c % 8));
        }

        return hash;
    }

    /**
     * @brief Hashes a string at compile time. Non-ASCII characters will be ignored.
     *
     * @param str
     * @param len
     * @return constexpr std::uint64_t
     */
    SYSCALL_FORCEINLINE constexpr key_t __hash_str(const wchar_t *str, const std::size_t len) noexcept
    {
        std::uint64_t hash = __generate_key();

        for (std::size_t i = 0; i < len; i++)
        {
            if (str[i] > 0x7f)
                continue;

            hash = hash ^ (str[i] << (str[i] % 8));
        }

        return hash;
    }

    /**
     * @brief Gets the PEB at runtime by reading the GS register.
     *
     * @return PPEB
     */
    SYSCALL_FORCEINLINE PPEB __get_peb() noexcept
    {
        return reinterpret_cast<PPEB>(__readgsqword(0x60));
    }

    inline std::map<key_t, syscall_index_t> __syscall_map = {}; // Maps a hash to a syscall index.
    inline const key_t NTDLL_HASH = __hash_str("ntdll.dll");

    SYSCALL_FORCEINLINE void __setup_cache()
    {
        // clear the map in case it's already populated
        if (!__syscall_map.empty())
            __syscall_map.clear();

        // get the ldr data table entry for ntdll
        PLDR_DATA_TABLE_ENTRY pNtDll = nullptr;
        {
            PPEB peb = __get_peb();
            PPEB_LDR_DATA ldr = peb->Ldr;

            for (PLIST_ENTRY pListEntry = ldr->InMemoryOrderModuleList.Flink; pListEntry != &ldr->InMemoryOrderModuleList; pListEntry = pListEntry->Flink)
            {
                PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                if (__hash_str(pEntry->BaseDllName.Buffer, pEntry->BaseDllName.Length / sizeof(wchar_t)) == NTDLL_HASH)
                {
                    pNtDll = pEntry;
                    break;
                }
            }
        }

        assert(pNtDll != nullptr);
        if (pNtDll == nullptr) // couldn't find ntdll
            return;

        // get the export directory
        PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint64_t>(pNtDll->DllBase) + reinterpret_cast<PIMAGE_DOS_HEADER>(pNtDll->DllBase)->e_lfanew);
        PIMAGE_DATA_DIRECTORY pExportDirectory = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        // get the export directory entries
        PIMAGE_EXPORT_DIRECTORY pExport = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<std::uint64_t>(pNtDll->DllBase) + pExportDirectory->VirtualAddress);
        std::uint32_t *pAddressOfFunctions = reinterpret_cast<std::uint32_t *>(reinterpret_cast<std::uint64_t>(pNtDll->DllBase) + pExport->AddressOfFunctions);
        std::uint32_t *pAddressOfNames = reinterpret_cast<std::uint32_t *>(reinterpret_cast<std::uint64_t>(pNtDll->DllBase) + pExport->AddressOfNames);
        std::uint16_t *pAddressOfNameOrdinals = reinterpret_cast<std::uint16_t *>(reinterpret_cast<std::uint64_t>(pNtDll->DllBase) + pExport->AddressOfNameOrdinals);

        // iterate through the export directory entries
        for (std::uint32_t i = 0; i < pExport->NumberOfFunctions; i++)
        {
            // get the function name
            const char *pName = reinterpret_cast<const char *>(reinterpret_cast<std::uint64_t>(pNtDll->DllBase) + pAddressOfNames[i]);

            // get the function address
            void *funcAddr = reinterpret_cast<void *>(reinterpret_cast<std::uint64_t>(pNtDll->DllBase) + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);

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
                        // hash the function name
                        key_t hash = __hash_str(pName);

                        // insert syscall into cache
                        __syscall_map[hash] = syscallNr;
                        continue;
                    }
                }
            }
        }
    }

    template <key_t hash, class syscall_t>
    SYSCALL_FORCEINLINE syscall_t __get_syscall()
    {
        // check if the cache is empty
        if (__syscall_map.empty())
            __setup_cache();

        // check if the cache is still empty
        if (__syscall_map.empty())
            return nullptr;

        // check if the hash is in the cache
        if (__syscall_map.find(hash) == __syscall_map.end())
            return nullptr;

        // get the syscall index from the cache
        syscall_index_t syscallIndex = __syscall_map[hash];

        // setup the syscall
        __setup_syscall(syscallIndex);

        // return the syscall
        return reinterpret_cast<syscall_t>(__invoke_syscall);
    }
}

#define SYSCALL(name) syscall::__get_syscall<syscall::__hash_str(#name), decltype(&name)>()
