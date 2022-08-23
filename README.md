# SYSCALL - x64 DYNAMIC SYSCALL INVOCATION

## Note

I did this in < 1h so the code is kinda messy but functional. Threading support is limited, tested on clang and msvc. This can be detected using instrumentation callbacks.

## Usage

```cpp
#include <syscall.hpp>

int main()
{
    SYSCALL(NtClose)((HANDLE)-1);
}
```

## IDA decompilation of output

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned __int16 v3; // r15
  PPEB_LDR_DATA v4; // rbx
  int v5; // eax
  struct _LIST_ENTRY *v6; // r9
  char *v7; // rdx
  struct _LIST_ENTRY *v8; // r8
  unsigned int v9; // er10
  __int64 v10; // rax
  __int64 v11; // rcx
  __int64 v12; // rdx
  __int64 v13; // rcx
  struct _LIST_ENTRY *v14; // r10
  __int64 v15; // rax
  unsigned __int16 v16; // r9
  _DWORD *v17; // rax
  __int64 v18; // rdi
  __int64 v19; // rsi
  unsigned int v20; // ebx
  __int64 v21; // r14
  char *v22; // rdx
  __int64 v23; // rcx
  char *v24; // r8
  __int64 v25; // r11
  __int64 v26; // rax
  char v27; // al
  _BYTE *i; // r8
  unsigned __int16 j; // dx
  char *v30; // rcx
  char v31; // al
  __int64 v33; // [rsp+20h] [rbp-40h] BYREF
  char v34; // [rsp+28h] [rbp-38h]
  char v35; // [rsp+29h] [rbp-37h] BYREF
  __int64 v36; // [rsp+30h] [rbp-30h] BYREF
  char v37; // [rsp+38h] [rbp-28h]
  char v38; // [rsp+39h] [rbp-27h] BYREF

  v3 = 0;
  v4 = NtCurrentPeb()->Ldr;
  v5 = Mtx_lock((_Mtx_t)&unk_140004050);
  if ( v5 )
  {
    std::_Throw_C_error(v5);
    JUMPOUT(0x1400013C6i64);
  }
  v6 = v4->InMemoryOrderModuleList.Flink;
  if ( v6 != &v4->InMemoryOrderModuleList )
  {
    while ( 1 )
    {
      if ( v6 )
      {
        v7 = (char *)&v33;
        v8 = v6[5].Flink;
        v9 = LOWORD(v6[4].Blink) >> 1;
        v33 = 0xC4B8DCD4C8DCBCBCui64;
        v34 = -12;
        v10 = 165484186i64;
        do
        {
          v11 = *v7++;
          v10 = 16777619 * (v10 ^ v11);
        }
        while ( v7 != &v35 );
        if ( v9 )
        {
          v12 = v9;
          do
          {
            v13 = LOWORD(v8->Flink);
            v8 = (struct _LIST_ENTRY *)((char *)v8 + 2);
            v10 = v13 + 33 * v10;
            --v12;
          }
          while ( v12 );
        }
        if ( v10 == 0xD4AC820174583FF2ui64 )
          break;
      }
      v6 = v6->Flink;
      if ( v6 == &v4->InMemoryOrderModuleList )
        goto LABEL_37;
    }
    v14 = v6[2].Flink;
    if ( v14 )
    {
      if ( LOWORD(v14->Flink) == 23117 )
      {
        v15 = SHIDWORD(v14[3].Blink);
        if ( *(_DWORD *)((char *)&v14->Flink + v15) == 17744 )
        {
          v16 = 0;
          v17 = (_DWORD *)((char *)v14 + *(unsigned int *)((char *)&v14[8].Blink + v15));
          v18 = (__int64)v14 + (unsigned int)v17[7];
          v19 = (__int64)v14 + (unsigned int)v17[8];
          v20 = v17[6];
          v21 = (__int64)v14 + (unsigned int)v17[9];
          if ( v20 )
          {
            while ( 1 )
            {
              v36 = 0x34313A38353A3232i64;
              v22 = (char *)&v36;
              v23 = 165484186i64;
              v24 = (char *)v14 + *(unsigned int *)(v19 + 4i64 * v16);
              v25 = (__int64)v14 + *(unsigned int *)(v18 + 4i64 * *(unsigned __int16 *)(v21 + 2i64 * v16));
              v36 = 0xC4B8DCD4C8DCBCBCui64;
              v37 = -12;
              do
              {
                v26 = *v22++;
                v23 = 16777619 * (v23 ^ v26);
              }
              while ( v22 != &v38 );
              v27 = *v24;
              for ( i = v24 + 1; v27; v27 = *(i - 1) )
              {
                ++i;
                v23 = v27 + 33 * v23;
              }
              if ( v23 == 0xA6653DE843EE5802ui64 )
                break;
              if ( ++v16 >= v20 )
                goto LABEL_37;
            }
            if ( v25 )
            {
              for ( j = 0; ; ++j )
              {
                while ( 1 )
                {
                  v30 = (char *)(v25 + j);
                  v31 = *v30;
                  if ( *v30 != 15 )
                    break;
                  if ( v30[1] == 5 )
                    goto LABEL_37;
                  ++j;
                }
                if ( v31 == -61 )
                  break;
                if ( v31 == 76 && v30[1] == -117 && v30[2] == -47 && v30[3] == -72 && !v30[6] && !v30[7] )
                {
                  v3 = *((_WORD *)v30 + 2);
                  break;
                }
              }
            }
          }
        }
      }
    }
  }
LABEL_37:
  sub_1400013D0(v3);
  Mtx_unlock((_Mtx_t)&unk_140004050);
  sub_1400013E1(-1i64);
  return 0;
}
```

## Credits:

* [HellsGate](https://github.com/am0nsec/HellsGate) for the invocation concept and the parsing logic
* [LazyImporter](https://github.com/JustasMasiulis/lazy_importer) for the api hashing and macro concept
