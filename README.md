# SYSCALL - x64 DYNAMIC SYSCALL INVOCATION

## Note

I did this in < 1h so the code is kinda messy but functional. Threading support is limited, tested on clang and msvc. This can be detected using instrumentation callbacks. Another thing to note is that this doesn't need any API imports by using the PEB/LDR.

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
  unsigned int v3; // er13
  __int64 v4; // rax
  LIST_ENTRY *v5; // rbx
  struct _LIST_ENTRY *v6; // r9
  unsigned int v7; // er10
  __int64 v8; // rcx
  struct _LIST_ENTRY *v9; // r15
  __int64 v10; // rax
  _DWORD *v11; // r12
  __int64 v12; // rcx
  unsigned __int16 v13; // r14
  __int64 v14; // rsi
  __int64 v15; // rbx
  char *v16; // rcx
  char v17; // al
  char *i; // rcx
  unsigned __int16 v19; // di
  char v20; // cl
  __int64 v22; // [rsp+20h] [rbp-50h]
  const char **v23; // [rsp+28h] [rbp-48h]
  __int128 v24; // [rsp+30h] [rbp-40h] BYREF
  char *v25; // [rsp+40h] [rbp-30h]
  const char **v26; // [rsp+48h] [rbp-28h] BYREF
  char v27; // [rsp+50h] [rbp-20h]
  char v28; // [rsp+51h] [rbp-1Fh] BYREF
  __int64 v29; // [rsp+58h] [rbp-18h] BYREF
  char v30; // [rsp+60h] [rbp-10h]
  char v31; // [rsp+61h] [rbp-Fh] BYREF

  v3 = 0;
  v4 = qword_140005000;
  if ( qword_140005000 == (_QWORD)xmmword_140005008 )
  {
    v25 = &byte_140005110;
    byte_140005110 = 1;
    v5 = &NtCurrentPeb()->Ldr->InMemoryOrderModuleList;
    v6 = v5->Flink;
    if ( v5->Flink == v5 )
      goto LABEL_11;
    while ( 1 )
    {
      if ( v6 )
      {
        v7 = LOWORD(v6[4].Blink) >> 1;
        envp = (const char **)v6[5].Flink;
        v26 = (const char **)0xC0B8DCCCB8DCC0B8i64;
        v27 = -12;
        v8 = 165484186i64;
        argv = (const char **)&v26;
        do
        {
          v8 = 16777619 * (v8 ^ *(char *)argv);
          argv = (const char **)((char *)argv + 1);
        }
        while ( argv != (const char **)&v28 );
        if ( v7 )
        {
          argv = (const char **)v7;
          do
          {
            v8 = *(unsigned __int16 *)envp + 33 * v8;
            envp = (const char **)((char *)envp + 2);
            argv = (const char **)((char *)argv - 1);
          }
          while ( argv );
        }
        if ( v8 == 0x17970714AF325F46i64 )
          break;
      }
      v6 = v6->Flink;
      if ( v6 == v5 )
        goto LABEL_11;
    }
    v9 = v6[2].Flink;
    if ( v9 )
    {
      if ( LOWORD(v9->Flink) == 23117 )
      {
        v10 = SHIDWORD(v9[3].Blink);
        if ( *(_DWORD *)((char *)&v9->Flink + v10) == 17744 )
        {
          v11 = (_DWORD *)((char *)v9 + *(unsigned int *)((char *)&v9[8].Blink + v10));
          v12 = (__int64)v9 + (unsigned int)v11[7];
          v22 = v12;
          argv = (const char **)((char *)v9 + (unsigned int)v11[8]);
          v23 = argv;
          envp = (const char **)((char *)v9 + (unsigned int)v11[9]);
          v26 = envp;
          v13 = 0;
          if ( v11[6] )
          {
LABEL_21:
            argv = (const char **)*((unsigned int *)argv + v13);
            v14 = (__int64)v9 + *(unsigned int *)(v12 + 4i64 * *((unsigned __int16 *)envp + v13));
            v29 = 0xC0B8DCCCB8DCC0B8ui64;
            v30 = -12;
            v15 = 165484186i64;
            v16 = (char *)&v29;
            do
              v15 = 16777619 * (v15 ^ *v16++);
            while ( v16 != &v31 );
            v17 = *((_BYTE *)&v9->Flink + (_QWORD)argv);
            for ( i = (char *)&v9->Flink + (_QWORD)argv + 1; v17; ++i )
            {
              v15 = v17 + 33 * v15;
              v17 = *i;
            }
            v19 = 0;
            while ( 1 )
            {
              v20 = *(_BYTE *)(v19 + v14);
              if ( v20 == 15 )
                break;
              if ( v20 == -61 )
              {
LABEL_28:
                if ( (unsigned int)++v13 < v11[6] )
                {
                  v12 = v22;
                  argv = v23;
                  envp = v26;
                  goto LABEL_21;
                }
                goto LABEL_11;
              }
              if ( v20 == 76
                && *(_BYTE *)(v19 + v14 + 1) == 0x8B
                && *(_BYTE *)(v19 + v14 + 2) == 0xD1
                && *(_BYTE *)(v19 + v14 + 3) == 0xB8
                && !*(_BYTE *)(v19 + v14 + 6)
                && !*(_BYTE *)(v19 + v14 + 7)
                && (argv = (const char **)*(unsigned __int16 *)(v19 + v14 + 4), *(_WORD *)(v19 + v14 + 4)) )
              {
                *(_QWORD *)&v24 = v15;
                DWORD2(v24) = (_DWORD)argv;
                argv = (const char **)xmmword_140005008;
                if ( (_QWORD)xmmword_140005008 == *((_QWORD *)&xmmword_140005008 + 1) )
                {
                  sub_140001020(&qword_140005000, xmmword_140005008, &v24);
                  goto LABEL_41;
                }
                *(_OWORD *)xmmword_140005008 = v24;
                *(_QWORD *)&xmmword_140005008 = xmmword_140005008 + 16;
                ++v19;
              }
              else
              {
LABEL_41:
                ++v19;
              }
            }
            if ( *(_BYTE *)(v19 + v14 + 1) == 5 )
              goto LABEL_28;
            goto LABEL_41;
          }
        }
      }
    }
LABEL_11:
    v4 = qword_140005000;
  }
  byte_140005110 = 1;
  if ( v4 != (_QWORD)xmmword_140005008 )
  {
    argv = (const char **)0x70DBEFBF9D509256i64;
    while ( *(_QWORD *)v4 != 0x70DBEFBF9D509256i64 )
    {
      v4 += 16i64;
      if ( v4 == (_QWORD)xmmword_140005008 )
        goto LABEL_43;
    }
    v3 = *(_DWORD *)(v4 + 8);
  }
LABEL_43:
  sub_140001810(v3, argv, envp);
  byte_140005110 = 0;
  sub_140001821(-1i64);
  return 0;
}
```

## Credits

* [HellsGate](https://github.com/am0nsec/HellsGate) for the invocation concept and the parsing logic
* [LazyImporter](https://github.com/JustasMasiulis/lazy_importer) for the api hashing and macro concept
