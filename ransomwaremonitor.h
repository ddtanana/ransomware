#pragma once
#ifndef RANSOMWARE_MONITOR_HPP
#define RANSOMWARE_MONITOR_HPP

#define RANSMON_FILE_PATH "C:\Ransomwaremonitor.log"

#include <windows.h>
#include <stdio.h>

#include <wincrypt.h>
#include <bcrypt.h>

#include <winternl.h>
#include <winioctl.h>

//
class RansomwareMonitorHelper
{

public :

    static DWORD dw_key_len;
    static PBYTE pb_key;
    static BOOL recursive;

    static void attach();
    static void detach();

    //
    void error(
               const char   *msg,
               int          eNumber);

    void saveExportKey(
                       HCRYPTKEY  hKey,
                       BYTE       *pbData);

    void clear();

};

//
class RansomwareMonitorLog
{

    FILE *logFile;

public :

    static void singleLine(const char *msg);

    RansomwareMonitorLog(const char *section_name);
    ~RansomwareMonitorLog();

    void nl();

    //

    template<typename T>
    void adds(T value);

    template<typename T>
    void addx(T value);

    template<typename T>
    void add02x(T value);

    //
    template<typename T>
    void appendd(
                 const char *name,
                 T          value);

    template<typename T>
    void appends(
                 const char *name,
                 T          value);

    template<typename T>
    void appendx(
                 const char *name,
                 T            value);

    //
    template<typename T>
    void begins(
                const char  *name,
                T           value);

    template<typename T>
    void beginx(
                const char  *name,
                T             value);

    //
    template<typename T>
    void lined(
               const char   *name,
               T            value);

    template<typename T>
    void lines(
               const char   *name,
               T            value);

    template<typename T>
    void linex(
               const char   *name,
               T              value);

    template<typename T>
    void linex(
               const char   *name1,
               T            value1,
               const char   *name2,
               const char   *value2);

    template<typename T>
    void linewZ(
                const char  *name,
                T           value);

};

/* Original functions */

/* Crypto API */
static BOOL (WINAPI *rwm_O_AcquireContext)(HCRYPTPROV *, LPCTSTR, LPCTSTR, DWORD, DWORD) = CryptAcquireContext;
static BOOL (WINAPI *rwm_O_CreateHash)(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH *) = CryptCreateHash;
static BOOL (WINAPI *rwm_O_Decrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE *, DWORD *) = CryptDecrypt;
static BOOL (WINAPI *rwm_O_DeriveKey)(HCRYPTPROV, ALG_ID, HCRYPTHASH, DWORD, HCRYPTKEY *) = CryptDeriveKey;
static BOOL (WINAPI *rwm_O_DestroyKey)(HCRYPTKEY hKey) = CryptDestroyKey;
static BOOL (WINAPI *rwm_O_Encrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE *, DWORD *, DWORD) = CryptEncrypt;
static BOOL (WINAPI *rwm_O_ExportKey)(HCRYPTKEY, HCRYPTKEY, DWORD, DWORD, BYTE *, DWORD *) = CryptExportKey;
static BOOL (WINAPI *rwm_O_GenKey)(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY *) = CryptGenKey;
static BOOL (WINAPI *rwm_O_GenRandom)(HCRYPTPROV, DWORD, BYTE *) = CryptGenRandom;
static BOOL (WINAPI *rwm_O_HashData)(HCRYPTHASH, const BYTE *, DWORD, DWORD) = CryptHashData;
static BOOL (WINAPI *rwm_O_ImportKey)(HCRYPTPROV, const BYTE *, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY *) = CryptImportKey;
static BOOL (WINAPI *rwm_O_SetKeyParam)(HCRYPTKEY, DWORD, const BYTE *, DWORD) = CryptSetKeyParam;

/* Files */
static HANDLE (WINAPI *rwm_O_CreateFile)(LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFile;
static HFILE (WINAPI *rwm_O_OpenFile)(LPCSTR, LPOFSTRUCT, UINT) = OpenFile;
static NTSTATUS (WINAPI *rwm_O_NtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG) = NtCreateFile;
static NTSTATUS (WINAPI *rwm_O_NtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG) = NtOpenFile;


/* Proxy functions */

/* Crypto API */
BOOL WINAPI rwm_P_AcquireContext(
                                 HCRYPTPROV *phProv,
                                 LPCTSTR    pszContainer,
                                 LPCTSTR    pszProvider,
                                 DWORD      dwProvType,
                                 DWORD      dwFlags);

BOOL WINAPI rwm_P_CreateHash(
                             HCRYPTPROV hProv,
                             ALG_ID     Algid,
                             HCRYPTKEY  hKey,
                             DWORD      dwFlags,
                             HCRYPTHASH *phHash);

BOOL WINAPI rwm_P_Decrypt(
                          HCRYPTKEY  hKey,
                          HCRYPTHASH hHash,
                          BOOL       Final,
                          DWORD      dwFlags,
                          BYTE       *pbData,
                          DWORD      *pdwDataLen);

BOOL WINAPI rwm_P_DeriveKey(
                            HCRYPTPROV hProv,
                            ALG_ID     Algid,
                            HCRYPTHASH hBaseData,
                            DWORD      dwFlags,
                            HCRYPTKEY  *phKey);

BOOL WINAPI rwm_P_DestroyKey(HCRYPTKEY hKey);

BOOL WINAPI rwm_P_Encrypt(
                          HCRYPTKEY  hKey,
                          HCRYPTHASH hHash,
                          BOOL       Final,
                          DWORD      dwFlags,
                          BYTE       *pbData,
                          DWORD      *pdwDataLen,
                          DWORD      dwBufLen);

BOOL WINAPI rwm_P_ExportKey(
                            HCRYPTKEY hKey,
                            HCRYPTKEY hExpKey,
                            DWORD     dwBlobType,
                            DWORD     dwFlags,
                            BYTE      *pbData,
                            DWORD     *pdwDataLen);

BOOL WINAPI rwm_P_GenKey(
                         HCRYPTPROV hProv,
                         ALG_ID     Algid,
                         DWORD      dwFlags,
                         HCRYPTKEY  *phKey
);

BOOL WINAPI rwm_P_GenRandom(
                            HCRYPTPROV hProv,
                            DWORD      dwLen,
                            BYTE       *pbBuffer);

BOOL WINAPI rwm_P_HashData(
                           HCRYPTHASH hHash,
                           BYTE       *pbData,
                           DWORD      dwDataLen,
                           DWORD      dwFlags);

BOOL WINAPI rwm_P_ImportKey(
                            HCRYPTPROV hProv,
                            BYTE       *pbData,
                            DWORD      dwDataLen,
                            HCRYPTKEY  hPubKey,
                            DWORD      dwFlags,
                            HCRYPTKEY  *phKey);

BOOL WINAPI rwm_P_SetKeyParam(
                              HCRYPTKEY hKey,
                              DWORD     dwParam,
                              BYTE      *pbData,
                              DWORD     dwFlags);

/* Files */
HANDLE WINAPI rwm_P_CreateFile(
                               LPCTSTR               lpFileName,
                               DWORD                 dwDesiredAccess,
                               DWORD                 dwShareMode,
                               LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                               DWORD                 dwCreationDisposition,
                               DWORD                 dwFlagsAndAttributes,
                               HANDLE                hTemplateFile);

HFILE WINAPI rwm_P_OpenFile(
                            LPCSTR     lpFileName,
                            LPOFSTRUCT lpReOpenBuff,
                            UINT       uStyle);

NTSTATUS WINAPI rwm_P_NtCreateFile(
                                   PHANDLE            FileHandle,
                                   ACCESS_MASK        DesiredAccess,
                                   POBJECT_ATTRIBUTES ObjectAttributes,
                                   PIO_STATUS_BLOCK   IoStatusBlock,
                                   PLARGE_INTEGER     AllocationSize,
                                   ULONG              FileAttributes,
                                   ULONG              ShareAccess,
                                   ULONG              CreateDisposition,
                                   ULONG              CreateOptions,
                                   PVOID              EaBuffer,
                                   ULONG              EaLength);

NTSTATUS WINAPI rwm_P_NtOpenFile(
                                 PHANDLE            FileHandle,
                                 ACCESS_MASK        DesiredAccess,
                                 POBJECT_ATTRIBUTES ObjectAttributes,
                                 PIO_STATUS_BLOCK   IoStatusBlock,
                                 ULONG              ShareAccess,
                                 ULONG              OpenOptions);

#endif // RANSOMWARE_MONITOR_HPP
