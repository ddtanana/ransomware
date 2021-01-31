#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <tchar.h>

#include <wincrypt.h>
#include <winternl.h>
#include <bcrypt.h>

#include "detours/detours.h"
#include "ransomwaremonitor.h"

#pragma comment (lib, "advapi32")
#pragma comment (lib, "user32")
#pragma comment (lib, "detours/detours")
#pragma comment (lib, "bcrypt.lib")
#pragma comment (lib, "ntdll")

//
RansomwareMonitorHelper rwm_HelperObj;

DWORD RansomwareMonitorHelper::dw_key_len = 0;
PBYTE RansomwareMonitorHelper::pb_key = NULL;
BOOL RansomwareMonitorHelper::recursive = FALSE;

/* HELPER */
void RansomwareMonitorHelper::attach()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    /* CryptoApi */
    DetourAttach( (PVOID *)(&rwm_O_AcquireContext), (PVOID)rwm_P_AcquireContext);
    DetourAttach( (PVOID *)(&rwm_O_CreateHash),     (PVOID)rwm_P_CreateHash    );
    DetourAttach( (PVOID *)(&rwm_O_Decrypt),        (PVOID)rwm_P_Decrypt       );
    DetourAttach( (PVOID *)(&rwm_O_DeriveKey),      (PVOID)rwm_P_DeriveKey     );
    DetourAttach( (PVOID *)(&rwm_O_Encrypt),        (PVOID)rwm_P_Encrypt       );
    DetourAttach( (PVOID *)(&rwm_O_ExportKey),      (PVOID)rwm_P_ExportKey     );
    DetourAttach( (PVOID *)(&rwm_O_GenKey),         (PVOID)rwm_P_GenKey        );
    DetourAttach( (PVOID *)(&rwm_O_GenRandom),      (PVOID)rwm_P_GenRandom     );
    DetourAttach( (PVOID *)(&rwm_O_HashData),       (PVOID)rwm_P_HashData      );
    DetourAttach( (PVOID *)(&rwm_O_ImportKey),      (PVOID)rwm_P_ImportKey     );
    DetourAttach( (PVOID *)(&rwm_O_SetKeyParam),    (PVOID)rwm_P_SetKeyParam   );

    /* Files */
    DetourAttach( (PVOID *)(&rwm_O_CreateFile),     (PVOID)rwm_P_CreateFile    );
    DetourAttach( (PVOID *)(&rwm_O_OpenFile),       (PVOID)rwm_P_OpenFile      );
    DetourAttach( (PVOID *)(&rwm_O_NtCreateFile),   (PVOID)rwm_P_NtCreateFile  );
    DetourAttach( (PVOID *)(&rwm_O_NtOpenFile),     (PVOID)rwm_P_NtOpenFile    );

    DetourTransactionCommit();
    RansomwareMonitorLog::singleLine("[SUCCESS] Hooked CryptoAPI\n");
}

void RansomwareMonitorHelper::detach()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    /* CryptoApi */
    DetourDetach( (PVOID *)(&rwm_O_AcquireContext), (PVOID)rwm_P_AcquireContext);
    DetourDetach( (PVOID *)(&rwm_O_CreateHash),     (PVOID)rwm_P_CreateHash    );
    DetourDetach( (PVOID *)(&rwm_O_Decrypt),        (PVOID)rwm_P_Decrypt       );
    DetourDetach( (PVOID *)(&rwm_O_DeriveKey),      (PVOID)rwm_P_DeriveKey     );
    DetourDetach( (PVOID *)(&rwm_O_Encrypt),        (PVOID)rwm_P_Encrypt       );
    DetourDetach( (PVOID *)(&rwm_O_ExportKey),      (PVOID)rwm_P_ExportKey     );
    DetourDetach( (PVOID *)(&rwm_O_GenKey),         (PVOID)rwm_P_GenKey        );
    DetourDetach( (PVOID *)(&rwm_O_GenRandom),      (PVOID)rwm_P_GenRandom     );
    DetourDetach( (PVOID *)(&rwm_O_HashData),       (PVOID)rwm_P_HashData      );
    DetourDetach( (PVOID *)(&rwm_O_ImportKey),      (PVOID)rwm_P_ImportKey     );
    DetourDetach( (PVOID *)(&rwm_O_SetKeyParam),    (PVOID)rwm_P_SetKeyParam   );

    /* Files */
    DetourDetach( (PVOID *)(&rwm_O_CreateFile),     (PVOID)rwm_P_CreateFile    );
    DetourDetach( (PVOID *)(&rwm_O_OpenFile),       (PVOID)rwm_P_OpenFile      );
    DetourDetach( (PVOID *)(&rwm_O_NtCreateFile),   (PVOID)rwm_P_NtCreateFile  );
    DetourDetach( (PVOID *)(&rwm_O_NtOpenFile),     (PVOID)rwm_P_NtOpenFile    );

    DetourTransactionCommit();

    rwm_HelperObj.clear();
}

//
void RansomwareMonitorHelper::error(
                                    const char  *msg,
                                    int         eNumber)
{
    fprintf(stderr, "An error occurred in the program. \n");
    fprintf(stderr, "%s\n", msg);
    fprintf(stderr, "Error number %x.\n", eNumber);

    RansomwareMonitorLog::singleLine(msg);
}

void RansomwareMonitorHelper::saveExportKey(
                                            HCRYPTKEY  hKey,
                                            BYTE       *pbData)
{
    if (RansomwareMonitorHelper::recursive == FALSE)
    {
        RansomwareMonitorHelper::recursive = TRUE;

        if (pbData == NULL)
        {
            // CryptEncrypt being used to get allocation size for cipher data
            if(!rwm_O_ExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &(RansomwareMonitorHelper::dw_key_len)))
            {
                error("[FAIL] Error computing BLOB length.", GetLastError());
            }

            RansomwareMonitorLog mon("");
            mon.lined("ExfilKeyLen", RansomwareMonitorHelper::dw_key_len);
        }
        else if (RansomwareMonitorHelper::dw_key_len != 0)
        {
            // CryptEncrypt is encrypting data, and was used to get the allocation size
            RansomwareMonitorHelper::pb_key = (BYTE *)malloc(RansomwareMonitorHelper::dw_key_len);

            if (!rwm_O_ExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, RansomwareMonitorHelper::pb_key, &(RansomwareMonitorHelper::dw_key_len)))
            {
                error("[FAIL] Error computing BLOB length.", GetLastError());
            }
            else
            {
                RansomwareMonitorLog mon("");
                mon.begins("ExfilKeyData", "");

                for (int i = 0; i < RansomwareMonitorHelper::dw_key_len; ++i)
                {
                    mon.add02x(RansomwareMonitorHelper::pb_key[i]);
                }

                mon.nl();
            }

            free(pb_key);
        }
        else
        {
            // CryptEncrypt is encrypting data, and was NOT called to get the alloca size
            // Do the export in one step.

            // Get the size to allocate for the export blob
            if(!rwm_O_ExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &(RansomwareMonitorHelper::dw_key_len)))
            {
                error("[FAIL] Error computing BLOB length.", GetLastError());
            }
            else
            {
                RansomwareMonitorHelper::pb_key = (BYTE *)malloc(RansomwareMonitorHelper::dw_key_len);

                // Get the export blob
                if (!rwm_O_ExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, RansomwareMonitorHelper::pb_key, &(RansomwareMonitorHelper::dw_key_len)))
                {
                    error(TEXT("[FAIL] Exfil key data failed."), GetLastError());
                }
                else
                {
                    RansomwareMonitorLog mon("");
                    mon.begins("no-alloca ExfilKeyData", "");

                    for (int i = 0; i < RansomwareMonitorHelper::dw_key_len; ++i)
                    {
                        mon.add02x(RansomwareMonitorHelper::pb_key[i]);
                    }

                    mon.nl();
                }

                free(pb_key);
            }
        }

        RansomwareMonitorHelper::recursive = FALSE;
    }
}

void RansomwareMonitorHelper::clear()
{
    RansomwareMonitorHelper::dw_key_len = 0;
    RansomwareMonitorHelper::pb_key = NULL;
    RansomwareMonitorHelper::recursive = FALSE;
}

/* LOG */
void RansomwareMonitorLog::singleLine(const char *msg)
{
    FILE *file = fopen(RANSMON_FILE_PATH, "a");
    fprintf(file, "%s\n", msg);
    fclose(file);
}

RansomwareMonitorLog::RansomwareMonitorLog(const char *section_name)
{
    logFile = fopen(RANSMON_FILE_PATH, "a");

    if (strlen(section_name))
    {
        SYSTEMTIME st;
        GetSystemTime(&st);
        fprintf(logFile, "[%s] %d:%d:%d %d\n", section_name, st.wHour, st.wMinute, st.wSecond , st.wMilliseconds);
    }
}

RansomwareMonitorLog::~RansomwareMonitorLog()
{
    fclose(logFile);
}

void RansomwareMonitorLog::nl()
{
    fprintf(logFile, "\n");
}

//
template <typename T>
void RansomwareMonitorLog::adds(T value)
{
    fprintf(logFile, "%s", value);
}

template <typename T>
void RansomwareMonitorLog::addx(T value)
{
    fprintf(logFile, "%x", value);
}

template <typename T>
void RansomwareMonitorLog::add02x(T value)
{
    fprintf(logFile, "%02x", value);
}

//
template <typename T>
void RansomwareMonitorLog::appendd(
                                   const char   *name,
                                   T            value)
{
    fprintf(logFile, ", %s = %d", name, value);
}

template <typename T>
void RansomwareMonitorLog::appends(
                                   const char   *name,
                                   T            value)
{
    fprintf(logFile, ", %s = %s", name, value);
}

template <typename T>
void RansomwareMonitorLog::appendx(
                                   const char   *name,
                                   T            value)
{
    fprintf(logFile, ", %s = %x", name, value);
}

//
template <typename T>
void RansomwareMonitorLog::begins(
                                  const char    *name,
                                  T             value)
{
    fprintf(logFile, "\t %s = %s", name, value);
}

template <typename T>
void RansomwareMonitorLog::beginx(
                                  const char    *name,
                                  T             value)
{
    fprintf(logFile, "\t %s = %x", name, value);
}

//
template <typename T>
void RansomwareMonitorLog::lined(
                                 const char *name,
                                 T          value)
{
    fprintf(logFile, "\t %s = %d\n", name, value);
}

template <typename T>
void RansomwareMonitorLog::lines(
                                 const char *name,
                                 T          value)
{
    fprintf(logFile, "\t %s = %s\n", name, value);
}

template <typename T>
void RansomwareMonitorLog::linex(
                                 const char *name,
                                 T          value)
{
    fprintf(logFile, "\t %s = %x\n", name, value);
}

template <typename T>
void RansomwareMonitorLog::linex(
                                 const char *name1,
                                 T          value1,
                                 const char *name2,
                                 const char *value2)
{
    fprintf(logFile, "\t %s = %x, %s = %s\n", name1, value1, name2, value2);
}

//
template <typename T>
void RansomwareMonitorLog::linewZ(
                                  const char    *name,
                                  T             value)
{
    fprintf(logFile, "\t %s = %wZ\n", name, value);
}

/* Crypto API */
BOOL WINAPI rwm_P_AcquireContext(
                                 HCRYPTPROV *phProv,
                                 LPCTSTR    pszContainer,
                                 LPCTSTR    pszProvider,
                                 DWORD      dwProvType,
                                 DWORD      dwFlags)
{
    RansomwareMonitorLog mon("CryptAcquireContext");

    mon.linex("HCRYPTPROV *phProv", phProv, "*phProv", "OUTPUT");
    mon.lines("LPCTSTR pszContainer", pszContainer);
    mon.lines("LPCTSTR pszProvider", pszProvider);
    mon.linex("DWORD dwProvType", dwProvType);
    mon.linex("DWORD dwFlags", dwFlags);

    return rwm_O_AcquireContext(phProv, pszContainer, pszProvider, dwProvType, dwFlags);
}

//
BOOL WINAPI rwm_P_CreateHash(
                             HCRYPTPROV hProv,
                             ALG_ID     Algid,
                             HCRYPTKEY  hKey,
                             DWORD      dwFlags,
                             HCRYPTHASH *phHash)
{
    RansomwareMonitorLog mon("CryptCreateHash");

    mon.linex("HCRYPTPROV hProv", hProv);
    mon.linex("ALG_ID Algid", Algid);
    mon.linex("HCRYPTKEY hKey", hKey);
    mon.linex("DWORD dwFlags", dwFlags);
    mon.linex("HCRYPTHASH *phHash", phHash, "*phHash", "OUTPUT");

    return rwm_O_CreateHash(hProv, Algid, hKey, dwFlags, phHash);
}

//
BOOL WINAPI rwm_P_Decrypt(
                          HCRYPTKEY  hKey,
                          HCRYPTHASH hHash,
                          BOOL       Final,
                          DWORD      dwFlags,
                          BYTE       *pbData,
                          DWORD      *pdwDataLen)
{
    RansomwareMonitorLog mon("CryptDecrypt");

    mon.linex("HCRYPTKEY hKey", hKey);
    mon.linex("HCRYPTHASH hHash", hHash);
    mon.linex("BOOL Final", Final);
    mon.linex("DWORD dwFlags", dwFlags);
    mon.linex("BYTE *pbData", pbData, "*pbdata", "BROKEN");

    mon.beginx("DWORD *pdwDataLen", pdwDataLen);

    if (pdwDataLen != NULL) mon.appendx("*pdwDataLen", *pdwDataLen);
    else mon.appends("*pdwDataLen", "NULL");

    mon.nl();

    return rwm_O_Decrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
}

//
BOOL WINAPI rwm_P_DeriveKey(
                            HCRYPTPROV hProv,
                            ALG_ID     Algid,
                            HCRYPTHASH hBaseData,
                            DWORD      dwFlags,
                            HCRYPTKEY  *phKey)
{
    RansomwareMonitorLog mon("CryptDeriveKey");

    mon.linex("HCRYPTPROV hProv", hProv);
    mon.linex("ALG_ID Algid", Algid);
    mon.linex("HCRYPTHASH hBaseData", hBaseData);
    mon.linex("DWORD dwFlags", dwFlags);
    mon.linex("HCRYPTKEY *phKey", phKey, "*phKey", "Cannot dereference the key directly");

    return rwm_O_DeriveKey(hProv, Algid, hBaseData, dwFlags | CRYPT_EXPORTABLE, phKey);
}

//
BOOL WINAPI rwm_P_DestroyKey(HCRYPTKEY hKey)
{
    RansomwareMonitorLog mon("CryptDestroyKey");
    RansomwareMonitorHelper::dw_key_len = 0;
    return rwm_O_DestroyKey(hKey);
}

//
BOOL WINAPI rwm_P_Encrypt(
                          HCRYPTKEY  hKey,
                          HCRYPTHASH hHash,
                          BOOL       Final,
                          DWORD      dwFlags,
                          BYTE       *pbData,
                          DWORD      *pdwDataLen,
                          DWORD      dwBufLen)
{
    {
        RansomwareMonitorLog mon("CryptEncrypt");

        mon.linex("HCRYPTKEY hKey", hKey);
        mon.linex("HCRYPTHASH hHash", hHash);
        mon.linex("BOOL Final", Final);
        mon.linex("DWORD dwFlags", dwFlags);
        mon.linex("BYTE *pbData", pbData, "*pbdata", "BROKEN");
        mon.linex("DWORD *pdwDataLen", pdwDataLen, "*pdwDataLen", "BROKEN");
        mon.linex("DWORD dwBufLen", dwBufLen);

        DWORD pdwDataLen2;
        BYTE pbData2[16];
        CryptGetKeyParam(hKey, KP_IV, NULL, &pdwDataLen2, 0);
        CryptGetKeyParam(hKey, KP_IV, pbData2, &pdwDataLen2, 0);

        mon.begins("KP_IV", "");

        for (int i = 0; i < pdwDataLen2; i++)
        {
            mon.add02x(pbData2[i]);
        }

        mon.nl();
    }

    rwm_HelperObj.saveExportKey(hKey, pbData);

    return rwm_O_Encrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
}

//
BOOL WINAPI rwm_P_ExportKey(
                            HCRYPTKEY hKey,
                            HCRYPTKEY hExpKey,
                            DWORD     dwBlobType,
                            DWORD     dwFlags,
                            BYTE      *pbData,
                            DWORD     *pdwDataLen)
{
    {
        RansomwareMonitorLog mon("CryptExportKey");

        mon.linex("HCRYPTKEY hKey", hKey);
        mon.linex("HCRYPTKEY hExpKey", hExpKey);
        mon.linex("DWORD dwBlobType", dwBlobType);
        mon.linex("DWORD dwFlags", dwFlags);
        mon.linex("BYTE* pbData", pbData, "*pbData", "BROKEN");
        mon.beginx("DWORD* pdwDataLen", pdwDataLen);
        mon.appendd("*pdwDataLen", *pdwDataLen);
        mon.nl();
    }

    rwm_HelperObj.saveExportKey(hKey, pbData);

    return rwm_O_ExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen);
}

//
BOOL WINAPI rwm_P_GenKey(
                         HCRYPTPROV hProv,
                         ALG_ID     Algid,
                         DWORD      dwFlags,
                         HCRYPTKEY  *phKey)
{
    RansomwareMonitorLog mon("CryptGenKey");

    mon.linex("HCRYPTPROV hProv", hProv);
    mon.linex("ALG_ID Algid", Algid);
    mon.linex("DWORD dwFlags", dwFlags);
    mon.linex("HCRYPTKEY* phKey", phKey, "*phKey", "Cannot dereference the key directly");

    return rwm_O_GenKey(hProv, Algid, dwFlags | CRYPT_EXPORTABLE, phKey);
}

//
BOOL WINAPI rwm_P_GenRandom(
                            HCRYPTPROV hProv,
                            DWORD      dwLen,
                            BYTE       *pbBuffer)
{
    RansomwareMonitorLog mon("CryptGenRandom");

    mon.linex("HCRYPTPROV hProv", hProv);
    mon.linex("DWORD dwLen", dwLen);
    mon.linex("BYTE* pbBuffer", pbBuffer, "*pbBuffer", "OUTPUT");

    BOOL result = rwm_O_GenRandom(hProv, dwLen, pbBuffer);

    mon.begins("RandomData", "");

    for (int i = 0 ; i < dwLen ; i++)
    {
        mon.add02x(pbBuffer[i]);
    }

    mon.nl();

    return result;
}

//
BOOL WINAPI rwm_P_HashData(
                           HCRYPTHASH hHash,
                           BYTE       *pbData,
                           DWORD      dwDataLen,
                           DWORD      dwFlags)
{
    RansomwareMonitorLog mon("CryptHashData");

    mon.linex("HCRYPTHASH hHash", hHash);
    mon.beginx("BYTE* pbData", pbData);

    if (pbData != NULL)
    {
        mon.appends("*pbData", "");

        for (int i = 0; i < dwDataLen; i++)
        {
            mon.add02x(pbData[i]);
        }
    }
    else mon.appends("*pbData", "NULL");

    mon.nl();
    mon.linex("DWORD dwDataLen", dwDataLen);
    mon.linex("DWORD dwFlags", dwFlags);

    return rwm_O_HashData(hHash, pbData, dwDataLen, dwFlags);
}

//
BOOL WINAPI rwm_P_ImportKey(
                            HCRYPTPROV hProv,
                            BYTE       *pbData,
                            DWORD      dwDataLen,
                            HCRYPTKEY  hPubKey,
                            DWORD      dwFlags,
                            HCRYPTKEY  *phKey)
{
    RansomwareMonitorLog mon("CryptImportKey");

    mon.linex("HCRYPTPROV hProv", hProv);
    mon.linex("BYTE* pbData", pbData, "*pbData", "BROKEN");
    mon.linex("DWORD dwDataLen", dwDataLen);
    mon.linex("HCRYPTKEY hPubKey", hPubKey);
    mon.linex("DWORD dwFlags", dwFlags);
    mon.linex("HCRYPTKEY* phKey", phKey, "*phKey", "BROKEN");

    return rwm_O_ImportKey(hProv, pbData, dwDataLen, hPubKey, dwFlags | CRYPT_EXPORTABLE, phKey);
}

//
BOOL WINAPI rwm_P_SetKeyParam(
                              HCRYPTKEY hKey,
                              DWORD     dwParam,
                              BYTE      *pbData,
                              DWORD     dwFlags)
{
    RansomwareMonitorLog mon("CryptSetKeyParam");

    mon.linex("HCRYPTKEY hKey", hKey);
    mon.linex("DWORD dwParam", dwParam);
    mon.beginx("BYTE* pbData", pbData);

    mon.linex("DWORD dwFlags", dwFlags);

    // Print out some key params
    DWORD pdwDataLen2;
    BYTE pbData2[16];
    CryptGetKeyParam(hKey, KP_IV, NULL, &pdwDataLen2, 0);
    CryptGetKeyParam(hKey, KP_IV, pbData2, &pdwDataLen2, 0);

    mon.begins("KP_IV", "");

    for (int i = 0; i < pdwDataLen2; i++)
    {
        mon.add02x(pbData2[i]);
    }

    mon.nl();

    return rwm_O_SetKeyParam(
                             hKey,
                             dwParam,
                             pbData,
                             dwFlags);
}

/* Files */
HANDLE WINAPI rwm_P_CreateFile(
                               LPCTSTR               lpFileName,
                               DWORD                 dwDesiredAccess,
                               DWORD                 dwShareMode,
                               LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                               DWORD                 dwCreationDisposition,
                               DWORD                 dwFlagsAndAttributes,
                               HANDLE                hTemplateFile)
{
    RansomwareMonitorLog mon("CreateFile");
    mon.lines("LPCSTR lpFileName", lpFileName);

    return rwm_O_CreateFile(
                            lpFileName,
                            dwDesiredAccess,
                            dwShareMode,
                            lpSecurityAttributes,
                            dwCreationDisposition,
                            dwFlagsAndAttributes,
                            hTemplateFile);
}

//
HFILE WINAPI rwm_P_OpenFile(
                            LPCSTR     lpFileName,
                            LPOFSTRUCT lpReOpenBuff,
                            UINT       uStyle)
{
    RansomwareMonitorLog mon("OpenFile");
    mon.lines("LPCSTR lpFileName", lpFileName);

    return rwm_O_OpenFile(lpFileName, lpReOpenBuff, uStyle);
}

//
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
                                   ULONG              EaLength)
{
    RansomwareMonitorLog mon("NtCreateFile");

    PUNICODE_STRING FileName = ObjectAttributes->ObjectName;
    mon.linewZ("PUNICODE_STRING FileName", FileName);

    return rwm_O_NtCreateFile(
                              FileHandle,
                              DesiredAccess,
                              ObjectAttributes,
                              IoStatusBlock,
                              AllocationSize,
                              FileAttributes,
                              ShareAccess,
                              CreateDisposition,
                              CreateOptions,
                              EaBuffer,
                              EaLength);
}

//
NTSTATUS WINAPI rwm_P_NtOpenFile(
                                 PHANDLE            FileHandle,
                                 ACCESS_MASK        DesiredAccess,
                                 POBJECT_ATTRIBUTES ObjectAttributes,
                                 PIO_STATUS_BLOCK   IoStatusBlock,
                                 ULONG              ShareAccess,
                                 ULONG              OpenOptions)
{
    RansomwareMonitorLog mon("NtOpenFile");

    PUNICODE_STRING FileName = ObjectAttributes->ObjectName;
    mon.linewZ("PUNICODE_STRING lpFileName", FileName);

    return rwm_O_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

/* Main */
BOOL WINAPI DllMain(
                    HMODULE hModule,
                    DWORD fdwReason,
                    LPVOID lpReserved)
{
    switch(fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        RansomwareMonitorHelper::attach();
        break;

    case DLL_PROCESS_DETACH:
        RansomwareMonitorHelper::detach();
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}
