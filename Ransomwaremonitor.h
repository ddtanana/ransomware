#pragma once
#ifndef NEWARS_H_
#define NEWARS_H_

#define _REP(first, second) first##second
#define _REP_3(f, s, t) f##s##t
#define _OLD_REP(word) Old##word
#define _NEW_REP(first, second) New##first##second
#define _CR_REP(word) Crypt##word
#define _CR_REP_2(first, second) Crypt##first##second

#define HCRPR HCRYPTPROV
#define HCRPH HCRYPTHASH
#define HCRPK HCRYPTKEY
#define BCRKH BCRYPT_KEY_HANDLE

#define _DD DetourDetach
#define _DA DetourAttach

#define SUCC "SUCCESS"

#define BCEC BCryptEncrypt
#define CDC CryptDecrypt
#define CGKP CryptGetKeyParam
#define CAC CryptAcquireContext

#define OTP "OUTPUT"
#define BRKN "BROKEN"

#define DWBT dwBlobType

#define QIT(word) "word"

#define X_0(val) 0x##val

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <Winternl.h>
#include <stdio.h>
#include <winioctl.h>

static BOOL(WINAPI* _REP(Old, Decrypt))(HCRPK, HCRPH, BOOL, DWORD, BYTE*, DWORD*) = _CR_REP(Decrypt);
static BOOL(WINAPI* _REP(Old, Encrypt))(HCRPK, HCRPH, BOOL, DWORD, BYTE*, DWORD*, DWORD) = _CR_REP(Encrypt);
static BOOL(WINAPI* _REP_3(New, CryptAcquire, Context))(HCRPR*, LPCTSTR, LPCTSTR, DWORD, DWORD) = _CR_REP_2(Acquire, Context);
static BOOL(WINAPI* _REP(Old, CreateHash))(HCRPR, ALG_ID, HCRPK, DWORD, HCRPH*) = _CR_REP_2(Create, Hash);
static BOOL(WINAPI* _REP(Old, HashData))(HCRPH, const BYTE*, DWORD, DWORD) = _CR_REP(HashData);
static BOOL(WINAPI* _REP(Old, DeriveKey))(HCRPR, ALG_ID, HCRPH, DWORD, HCRPK*) = _CR_REP_2(Derive, Key);
static BOOL(WINAPI* _REP(Old, GenKey))(HCRPR, ALG_ID, DWORD, HCRPK*) = _CR_REP(GenKey);
static BOOL(WINAPI* _REP(Old, ImportKey))(HCRPR, const BYTE*, DWORD, HCRPK, DWORD, HCRPK*) = _CR_REP_2(Import, Key);
static BOOL(WINAPI* _REP(Old, ExportKey))(HCRPK, HCRPK, DWORD, DWORD, BYTE*, DWORD*) = _CR_REP_2(Export, Key);
static BOOL(WINAPI* _REP(Old, GenRandom))(HCRPR, DWORD, BYTE*) = _CR_REP_2(Gen, Random);
static BOOL(WINAPI* _REP(Old, SetKeyParam))(HCRPK, DWORD, const BYTE*, DWORD) = _CR_REP_2(SetKey, Param);
static BOOL(WINAPI* _REP(Old, DestroyKey))(HCRPK) = _CR_REP_2(Destroy, Key);

static HFILE(WINAPI* OldOpenFile)(LPCSTR, LPOFSTRUCT, UINT) = OpenFile;
static NTSTATUS(WINAPI* OldNtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG) = NtOpenFile;
static HANDLE(WINAPI* OldCreateFile)(LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFile;
static NTSTATUS(WINAPI* OldNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG) = NtCreateFile;
static VOID(__thiscall* OldHSig)(void*, const BYTE*, size_t, DWORD*) = NULL;
static NTSTATUS(WINAPI* OldBCryEnc)(BCRKH, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG) = BCEC;

BOOL WINAPI _REP(New, SetKeyParam)(HCRPK, DWORD, BYTE*, DWORD);
BOOL WINAPI _REP(New, Decrypt)(HCRPK, HCRPH, BOOL, DWORD, BYTE*, DWORD*);
BOOL WINAPI _REP(New, Encrypt)(HCRPK, HCRPH, BOOL, DWORD, BYTE*, DWORD*, DWORD);
BOOL WINAPI _REP_3(Old, CryptAcquire, Context)(HCRPR*, LPCTSTR, LPCTSTR, DWORD, DWORD);
BOOL WINAPI _REP(New, CreateHash)(HCRPR, ALG_ID, HCRPK, DWORD, HCRPH*);
BOOL WINAPI _REP(New, HashData)(HCRPH, BYTE*, DWORD, DWORD);
BOOL WINAPI _REP(New, DeriveKey)(HCRPR, ALG_ID, HCRPH, DWORD, HCRPK*);
BOOL WINAPI _REP(New, GenKey)(HCRPR, ALG_ID, DWORD, HCRPK*);
BOOL WINAPI _REP(New, ImportKey)(HCRPR, BYTE*, DWORD, HCRPK, DWORD, HCRPK*);
BOOL WINAPI _REP(New, ExportKey)(HCRPK, HCRPK, DWORD, DWORD, BYTE*, DWORD*);
BOOL WINAPI _REP(New, GenRandom)(HCRPR, DWORD, BYTE*);
BOOL WINAPI _REP(New, DestroyKey)(HCRPK);

HFILE WINAPI NewOpenFile(LPCSTR, LPOFSTRUCT, UINT);
NTSTATUS WINAPI NewNtOpenFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
HANDLE WINAPI NewCreateFile(LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
NTSTATUS WINAPI NewNtCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

VOID __fastcall NewHSig(void*, void*, const BYTE*, size_t, DWORD*);
NTSTATUS WINAPI NewBCryptEncrypt(BCRKH, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);

unsigned char* memorySearch(char*, char, size_t);
size_t arraySearch(char*, char, size_t, char*, size_t, size_t);
const std::string cTime();
void MHE(LPTSTR, int);

#endif //NEWARS_H_
