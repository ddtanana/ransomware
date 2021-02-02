#include <stdio.h>
#include <windows.h>
#include <string>
#include <wincrypt.h>
#include <bcrypt.h>
#include "detours/detours.h"
#include <tchar.h>
#include "ransomwaremonitor.h"

#pragma comment (lib, "advapi32")
#pragma comment (lib, "user32")
#pragma comment (lib, "detours/detours")
#pragma comment (lib, "bcrypt.lib")
#pragma comment (lib, "ntdll")

static DWORD gDwKBE = 0;
static PBYTE gPKBE = NULL;
static BOOL rsv = FALSE;
static BOOL rsv2 = FALSE;

const DWORD NDL_SIZE = 32;
char NDL[NDL_SIZE] = { X_0(55), X_0(89), X_0(E5), X_0(53), X_0(83), X_0(EC), X_0(24), X_0(89), X_0(4D), X_0(F4), X_0(8B), X_0(45), X_0(F4), X_0(8B), X_0(55), X_0(0C),
					   X_0(89), X_0(14), X_0(24), X_0(89), X_0(C1), X_0(E8), X_0(8A), X_0(02), X_0(00), X_0(00), X_0(83), X_0(EC), X_0(04), X_0(8B), X_0(45), X_0(00) };

int tutt1 = 0x123123;
int tutt2 = 0x123123;
int tutt3 = 0x123123;
int tutt4 = 0x123123;
char NDL_END = 0xF4;

BOOL WINAPI _REP(New, Decrypt)(HCRPK hKey, HCRPH hHash, BOOL Final, DWORD dwFlags, BYTE* pbd, DWORD* pbdd) {
	FILE* fd = fopen("C:\\ransomwaremonitor.log", "a");
	std::string m_time = cTime();

	fprintf(fd, "[%s] %s\n", QIT(CDC), m_time.c_str());
	fprintf(fd, "\t %s hKey = %x\n", QIT(HCRPK), hKey);
	fprintf(fd, "\t %s hHash = %x\n", QIT(HCRPH), hHash);
	fprintf(fd, "\t BOOL Final = %x\n", Final);
	fprintf(fd, "\t DWORD dwFlags = %x\n", dwFlags);
	fprintf(fd, "\t BYTE* %s = %x, *pbdata = %s\n", "pbData", pbd, BRKN);
	fprintf(fd, "\t DWORD* %s =  %x, *pdwDataLen = ", "pdwDataLen", pbdd);
	if (pbdd != NULL) {
		fprintf(fd, "%x", *pbdd);
	}
	else {
		fprintf(fd, "NULL");
	}
	fprintf(fd, "\n");

	fclose(fd);
	return _REP(Old, Decrypt)(hKey, hHash, Final, dwFlags, pbd, pbdd);
}

BOOL WINAPI _REP(New, SetKeyParam)(HCRPK hKey, DWORD dwParam, BYTE* pbd, DWORD dwFlags) {
	FILE* fd = fopen("C:\\ransomwaremonitor.log", "a");
	std::string m_time = cTime();

	fprintf(fd, "[%s] %s\n", "CryptSetKeyParam", m_time.c_str());
	fprintf(fd, "\t %s hKey = %x\n", QIT(HCRPK), hKey);
	fprintf(fd, "\t DWORD dwParam = %x\n", dwParam);
	fprintf(fd, "\t BYTE* pbData = %x, *pbData = ", pbd);
	if (pbd != NULL) {
		fprintf(fd, "%x%x%x%x", "This requires", "extra work, as ", "pbData depends on the", "value of dwParam");
	}
	else {
		fprintf(fd, "NULL");
	}
	fprintf(fd, "\n");
	fprintf(fd, "\t DWORD dwFlags = %x\n", dwFlags);

	DWORD dwCount;
	BYTE pbd2[16];
	CGKP(hKey, KP_IV, NULL, &dwCount, 0);
	CGKP(hKey, KP_IV, pbd2, &dwCount, 0);
	fprintf(fd, "KP_IV =  ");
	for (int i = 0; i < dwCount; i++) {
		fprintf(fd, "%02x ", pbd2[i]);
	}

	fclose(fd);
	return _REP(Old, SetKeyParam)(hKey, dwParam, pbd, dwFlags);
}

BOOL WINAPI _REP(New, Encrypt)(HCRPK hKey, HCRPH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdDL, DWORD dwBL) {
	FILE* fd = fopen("C:\\ransomwaremonitor.log", "a");
	std::string m_time = cTime();

	fprintf(fd, "[%s] %s\n", "CryptEncrypt", m_time.c_str());
	fprintf(fd, "\t %s hKey = %x\n", QIT(HCRPK), hKey);
	fprintf(fd, "\t %s hHash = %x\n", QIT(HCRPH), hHash);
	fprintf(fd, "\t BOOL %s = %x\n", "Final", Final);
	fprintf(fd, "\t DWORD dwFlags = %x\n", dwFlags);
	fprintf(fd, "\t BYTE* pbData = %x, *pbdata = %s\n", pbData, BRKN);
	fprintf(fd, "\t DWORD* %s =  %x, *%s =  %s\n", "pdwDataLen", pdDL, "pdwDataLen", BRKN);
	fprintf(fd, "\t DWORD %s = %x\n", "dwBufLen", dwBL);
	fclose(fd);

	DWORD dwCount;
	BYTE pbd2[16];
	CGKP(hKey, KP_IV, NULL, &dwCount, 0);
	CGKP(hKey, KP_IV, pbd2, &dwCount, 0);
	fprintf(fd, "KP_IV =  ");
	for (int i = 0; i < dwCount; i++) {
		fprintf(fd, "%02x ", pbd2[i]);
	}

	if (rsv == FALSE) {
		rsv = TRUE;
		FILE* fd = fopen("C:\\ransomwaremonitor.log", "a");
		if (pbData == NULL) {
			if (!_REP(Old, ExportKey)(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &gDwKBE)) {
				MHE(TEXT("[ERR] Exf key length failed \n"), GetLastError());
				fprintf(fd, "[ERR] Exf key length failed \n");
			}
			fprintf(fd, "\t %s%s = %d\n", "ExfilKey", "Len", gDwKBE);
		}
		else if (gDwKBE != NULL) {
			gPKBE = (BYTE*)malloc(gDwKBE);
			if (!_REP(Old, ExportKey)(hKey, NULL, PLAINTEXTKEYBLOB, 0, gPKBE, &gDwKBE)) {
				MHE(TEXT("[ERR] Exf key length failed \n"), GetLastError());
				fprintf(fd, "[ERR] Exf key data failed \n");
			}
			fprintf(fd, "\t %s%s = ", "ExfilKey", "Data");
			for (int i = 0; i < gDwKBE; i++) {
				fprintf(fd, "%02x", gPKBE[i]);
			}
			fprintf(fd, "\n");
		}
		else {
			if (!_REP(Old, ExportKey)(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &gDwKBE)) {
				MHE(TEXT("[ERR] no-alloc Exf key length failed \n"), GetLastError());
				fprintf(fd, "[ERR] no-alloc Exf key length failed \n");
			}

			gPKBE = (BYTE*)malloc(gDwKBE);

			if (!_REP(Old, ExportKey)(hKey, NULL, PLAINTEXTKEYBLOB, 0, gPKBE, &gDwKBE)) {
				MHE(TEXT("[ERR] Exf key data failed \n"), GetLastError());
				fprintf(fd, "[ERR] no-alloc Exf key data failed \n");
			}

			fprintf(fd, "\t no-alloc %s%s = ", "ExfilKey", "Data");
			for (int i = 0; i < gDwKBE; i++) {
				fprintf(fd, "%02x", gPKBE[i]);
			}
			fprintf(fd, "\n");
		}
		fclose(fd);
		rsv = FALSE;
	}

	return _REP(Old, Encrypt)(hKey, hHash, Final, dwFlags, pbData, pdDL, dwBL);
}

BOOL WINAPI _REP_3(Old, CryptAcquire, Context)(HCRPR* phProv, LPCTSTR pszContainer, LPCTSTR pszProvider, DWORD dwProvType, DWORD dwFlags) {
	FILE* fd = fopen("C:\\ransomwaremonitor.log", "a");
	std::string m_time = cTime();

	fprintf(fd, "[%s] %s\n", QIT(CAC), m_time.c_str());
	fprintf(fd, "\t %s* phProv = %x, *phProv = %s%s\n", QIT(HCRPR), phProv, "OUTPUT, so probably", "can't deref NULL");
	fprintf(fd, "\t LPCTSTR pszContainer = %s\n", pszContainer);
	fprintf(fd, "\t LPCTSTR pszProvider = %s\n", pszProvider);
	fprintf(fd, "\t DWORD dwProvType = %x\n", dwProvType);
	fprintf(fd, "\t DWORD dwFlags = %x\n", dwFlags);

	fclose(fd);
	return _REP_3(New, CryptAcquire, Context)(phProv, pszContainer, pszProvider, dwProvType, dwFlags);
}

BOOL WINAPI _REP(New, CreateHash)(HCRPR hProv, ALG_ID Algid, HCRPK hKey, DWORD dwFlags, HCRPH* phHash) {
	FILE* fd = fopen("C:\\ransomwaremonitor.log", "a");
	std::string m_time = cTime();

	fprintf(fd, "[%s] %s\n", "CryptCreateHash", m_time.c_str());
	fprintf(fd, "\t %s hProv = %x\n", QIT(HCRPR), hProv);
	fprintf(fd, "\t ALG_ID Algid = %x\n", Algid);
	fprintf(fd, "\t %s hKey = %x\n", QIT(HCRPK), hKey);
	fprintf(fd, "\t DWORD dwFlags = %x\n", dwFlags);
	fprintf(fd, "\t %s* phHash = %x, *phHash = %s%s\n", QIT(HCRPH), phHash, "OUTPUT, so probably", "can't deref NULL");

	fclose(fd);
	return _REP(Old, CreateHash)(hProv, Algid, hKey, dwFlags, phHash);
}

BOOL WINAPI _REP(New, HashData)(HCRPH hHash, BYTE* pbData, DWORD dwDL, DWORD dwFlags) {
	FILE* fd = fopen("C:\\ransomwaremonitor.log", "a");
	std::string m_time = cTime();

	fprintf(fd, "[%s] %s\n", "CryptHashData", m_time.c_str());
	fprintf(fd, "\t %s hHash = %x\n", QIT(HCRPH), hHash);
	fprintf(fd, "\t BYTE* pbData = %x, *pbData = ", pbData);
	if (pbData != NULL) {
		for (int i = 0; i < dwDL; i++) {
			fprintf(fd, "%x", pbData[i]);
		}
	}
	else {
		fprintf(fd, "NULL");
	}
	fprintf(fd, "\n");
	fprintf(fd, "\t DWORD %s = %x\n", "dwDataLen", dwDL);
	fprintf(fd, "\t DWORD dwFlags = %x\n", dwFlags);

	fclose(fd);
	return _REP(Old, HashData)(hHash, pbData, dwDL, dwFlags);
}

BOOL WINAPI _REP(New, DeriveKey)(HCRPR hProv, ALG_ID algd, HCRPH hBaseData, DWORD dwFlags, HCRPK* phKey) {
	FILE* fd = fopen("C:\\ransomwaremonitor.log", "a");
	std::string m_time = cTime();

	fprintf(fd, "[%s] %s\n", "CryptDeriveKey", m_time.c_str());
	fprintf(fd, "\t %s hProv = %x\n", QIT(HCRPR), hProv);
	fprintf(fd, "\t ALG_ID %s = %x\n", "Algid", algd);
	fprintf(fd, "\t %s %s = %x\n", QIT(HCRPH), "hBaseData", hBaseData);
	fprintf(fd, "\t DWORD dwFlags = %x\n", dwFlags);
	fprintf(fd, "\t %s* phKey = %x, *phKey = %s%s\n", QIT(HCRPK), phKey, "Cannot deref the", "key directly");

	fclose(fd);
	return _REP(Old, DeriveKey)(hProv, algd, hBaseData, dwFlags | CRYPT_EXPORTABLE, phKey);
}

BOOL WINAPI _REP(New, GenKey)(HCRPR hProv, ALG_ID algd, DWORD dwFlags, HCRPK* phKey) {
	FILE* fd = fopen("C:\\ransomwaremonitor.log", "a");
	std::string m_time = cTime();

	fprintf(fd, "[%s] %s\n", "CryptGenKey", m_time.c_str());
	fprintf(fd, "\t %s hProv = %x\n", QIT(HCRPR), hProv);
	fprintf(fd, "\t ALG_ID %s = %x\n", "Algid", algd);
	fprintf(fd, "\t DWORD dwFlags = %x\n", dwFlags);
	fprintf(fd, "\t %s* phKey = %x, *phKey = %s%s\n", QIT(HCRPK), phKey, "Cannot deref the", "key directly");

	fclose(fd);
	return _REP(Old, GenKey)(hProv, algd, dwFlags | CRYPT_EXPORTABLE, phKey);
}

BOOL WINAPI _REP(New, GenRandom)(HCRPR hProv, DWORD dwLen, BYTE* pbBuffer) {
	FILE* fd = fopen("C:\\ransomwaremonitor.log", "a");
	std::string m_time = cTime();

	fprintf(fd, "[%s] %s\n", "CryptGenRandom", m_time.c_str());
	fprintf(fd, "\t %s hProv = %x\n", QIT(HCRPR), hProv);
	fprintf(fd, "\t DWORD dwLen = %x\n", dwLen);
	fprintf(fd, "\t BYTE* pbBuffer = %x, *pbBuffer = %s, cannot deref\n", OTP, pbBuffer);

	BOOL ret = _REP(Old, GenRandom)(hProv, dwLen, pbBuffer);

	fprintf(fd, "\t %s = ", "RandomData");
	for (int i = 0; i < dwLen; i++) {
		fprintf(fd, "%02x", pbBuffer[i]);
	}
	fprintf(fd, "\n");

	fclose(fd);
	return ret;
}

BOOL WINAPI _REP(New, ImportKey)(HCRPR hProv, BYTE* pbData, DWORD dwDL, HCRPK hPubKey, DWORD dwFlags, HCRPK* phKey) {
	FILE* fd = fopen("C:\\ransomwaremonitor.log", "a");
	std::string m_time = cTime();

	fprintf(fd, "[%s] %s\n", "CryptImportKey", m_time.c_str());
	fprintf(fd, "\t %s hProv = %x\n", QIT(HCRPR), hProv);
	fprintf(fd, "\t BYTE* pbData = %x, *pbData = %s\n", pbData, BRKN);
	fprintf(fd, "\t DWORD %s = %x\n", "dwDataLen", dwDL);
	fprintf(fd, "\t % hPubKey = %x\n", QIT(HCRPK), hPubKey);
	fprintf(fd, "\t DWORD dwFlags = %x\n", dwFlags);
	fprintf(fd, "\t %s* phKey = %x, *phKey = %s\n", QIT(HCRPK), phKey, BRKN);

	fclose(fd);
	return _REP(Old, ImportKey)(hProv, pbData, dwDL, hPubKey, dwFlags | CRYPT_EXPORTABLE, phKey);
}

BOOL WINAPI _REP(New, ExportKey)(HCRPK hKey, HCRPK hExpKey, DWORD dwbt, DWORD dwFlags,	BYTE* pbData, DWORD* pdDL) {
	FILE* fd = fopen("C:\\ransomwaremonitor.log", "a");
	std::string m_time = cTime();

	fprintf(fd, "[%s] %s\n", "CryptExportKey", m_time.c_str());
	fprintf(fd, "\t %s hKey = %x\n", QIT(HCRPK), hKey);
	fprintf(fd, "\t %s hExpKey = %x\n", QIT(HCRPK), hExpKey);
	fprintf(fd, "\t DWORD %s = %x\n", QIT(DWBT), dwbt);
	fprintf(fd, "\t DWORD dwFlags = %x\n", dwFlags);
	fprintf(fd, "\t BYTE* pbData = %x, *pbData = %s\n", pbData, BRKN);
	fprintf(fd, "\t DWORD* %s =  %x, *%s =  %d\n", "pdwDataLen", pdDL, "pdwDataLen", *pdDL);
	fclose(fd);

	if (rsv == FALSE) {
		rsv = TRUE;
		FILE* fd = fopen("C:\\ransomwaremonitor.log", "a");
		if (pbData == NULL) {
			if (!_REP(Old, ExportKey)(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &gDwKBE)) {
				MHE(TEXT("[ERR] Exf key length failed \n"), GetLastError());
				fprintf(fd, "[ERR] Exf key length failed \n");
			}
			fprintf(fd, "\t %s%s = %d\n", "ExfilKey", "Len", gDwKBE);
		}
		else if (gDwKBE != NULL) {
			gPKBE = (BYTE*)malloc(gDwKBE);
			if (!_REP(Old, ExportKey)(hKey, NULL, PLAINTEXTKEYBLOB, 0, gPKBE, &gDwKBE)) {
				MHE(TEXT("[ERR] Exf key data failed \n"), GetLastError());
				fprintf(fd, "[ERR] Exf key data failed \n");
			}
			fprintf(fd, "\t %s%s = ", "ExfilKey", "Data");
			for (int i = 0; i < gDwKBE; i++) {
				fprintf(fd, "%02x", gPKBE[i]);
			}
			fprintf(fd, "\n");
		}
		else {
			if (!_REP(Old, ExportKey)(hKey, NULL, PLAINTEXTKEYBLOB, 0, NULL, &gDwKBE)) {
				MHE(TEXT("[ERR] Exf key length failed \n"), GetLastError());
				fprintf(fd, "[ERR] Exf key length failed \n");
			}

			gPKBE = (BYTE*)malloc(gDwKBE);

			if (!_REP(Old, ExportKey)(hKey, NULL, PLAINTEXTKEYBLOB, 0, gPKBE, &gDwKBE)) {
				MHE(TEXT("[ERR] Exf key data failed \n"), GetLastError());
				fprintf(fd, "[ERR] Exf key data failed \n");
			}

			fprintf(fd, "\t %s%s = ", "ExfilKey", "Data");
			for (int i = 0; i < gDwKBE; i++) {
				fprintf(fd, "%02x", gPKBE[i]);
			}
			fprintf(fd, "\n");
		}
		fclose(fd);
		rsv = FALSE;
	}

	return _REP(Old, ExportKey)(hKey, hExpKey, dwbt, dwFlags, pbData, pdDL);
}

NTSTATUS WINAPI NewBCryptEncrypt(BCRKH hKey, PUCHAR pbInput, ULONG cbInput, VOID* pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags) {
	FILE* fd = fopen("C:\\ransomwaremonitor.log", "a");
	std::string m_time = cTime();

	fprintf(fd, "[%s] %s\n", QIT(BCEC), m_time.c_str());
	fclose(fd);

	return OldBCryEnc(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
}

HFILE WINAPI NewOpenFile(LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle) {
	FILE* fd = fopen("C:\\ransomwaremonitor.log", "a");
	std::string m_time = cTime();

	fprintf(fd, "[%s] %s\n", "OpenFile", m_time.c_str());
	fprintf(fd, "\t LPCSTR lpFileName = %s\n", lpFileName);
	fclose(fd);

	return OldOpenFile(lpFileName, lpReOpenBuff, uStyle);
}

NTSTATUS WINAPI NewNtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
	FILE* fd = fopen("C:\\ransomwaremonitor.log", "a");
	std::string m_time = cTime();

	PUNICODE_STRING FileName = ObjectAttributes->ObjectName;
	fprintf(fd, "[NtOpenFile] %s\n", m_time.c_str());
	fprintf(fd, "\t PUNICODE_STRING lpFileName = %wZ\n", FileName);
	fclose(fd);

	return OldNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

HANDLE WINAPI NewCreateFile(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
	FILE* fd = fopen("C:\\ransomwaremonitor.log", "a");
	std::string m_time = cTime();

	fprintf(fd, "[CreateFile] %s\n", m_time.c_str());
	fprintf(fd, "\t LPCSTR lpFileName = %s\n", lpFileName);
	fclose(fd);

	return OldCreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

NTSTATUS WINAPI NewNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
	if (rsv2 == FALSE) {
		rsv2 = TRUE;
		FILE* fd = fopen("C:\\ransomwaremonitor.log", "a");
		std::string m_time = cTime();
		fprintf(fd, "[NtCreateFile] %s\n", m_time.c_str());
		PUNICODE_STRING FileName = ObjectAttributes->ObjectName;
		fprintf(fd, "\t PUNICODE_STRING FileName = %wZ\n", FileName);
		fclose(fd);

		if (OldHSig == NULL) {
			unsigned char* sg_addr = memorySearch(NDL, NDL_END, NDL_SIZE);
			if (sg_addr != NULL) {
				OldHSig = (void(__thiscall*)(void*, const BYTE*, size_t, DWORD*))sg_addr;
				DetourTransactionBegin();
				DetourUpdateThread(GetCurrentThread());
				_DA(&(PVOID&)OldHSig, NewHSig);
				DetourTransactionCommit();
			}
		}

		if (OldHSig != NULL) {}

		rsv2 = FALSE;
	}
	return OldNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

VOID __fastcall NewHSig(void* This, void* throwaway, const BYTE* key, size_t length, DWORD* whatever) {
	FILE* fd = fopen("C:\\ransomwaremonitor.log", "a");
	fprintf(fd, "\t CryptoPPKey = ");
	for (int i = 0; i < length; i++) {
		fprintf(fd, "%02x", key[i]);
	}
	fprintf(fd, "\n");
	fclose(fd);
	return OldHSig(This, key, length, whatever);
}

INT APIENTRY DllMain(HMODULE hModule, DWORD Rsn, LPVOID lpReserved) {
	FILE* fd = fopen("C:\\ransomwaremonitor.log", "a");

	switch (Rsn) {
	case DLL_PROCESS_ATTACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		_DA(&(PVOID&)_REP(Old, Encrypt), _REP(New, Encrypt));
		_DA(&(PVOID&)_REP(Old, Decrypt), _REP(New, Decrypt));
		_DA(&(PVOID&)_REP_3(New, CryptAcquire, Context), _REP_3(Old, CryptAcquire, Context));
		_DA(&(PVOID&)_REP(Old, SetKeyParam), _REP(New, SetKeyParam));
		_DA(&(PVOID&)_REP(Old, CreateHash), _REP(New, CreateHash));
		_DA(&(PVOID&)_REP(Old, HashData), _REP(New, HashData));
		_DA(&(PVOID&)_REP(Old, DeriveKey), _REP(New, DeriveKey));
		_DA(&(PVOID&)_REP(Old, GenKey), _REP(New, GenKey));
		_DA(&(PVOID&)_REP(Old, ImportKey), _REP(New, ImportKey));
		_DA(&(PVOID&)_REP(Old, ExportKey), _REP(New, ExportKey));
		_DA(&(PVOID&)_REP(Old, GenRandom), _REP(New, GenRandom));
		_DA(&(PVOID&)OldOpenFile, NewOpenFile);
		_DA(&(PVOID&)OldNtOpenFile, NewNtOpenFile);
		_DA(&(PVOID&)OldCreateFile, NewCreateFile);
		_DA(&(PVOID&)OldNtCreateFile, NewNtCreateFile);
		_DA(&(PVOID&)OldBCryEnc, NewBCryptEncrypt);
		DetourTransactionCommit();

		fprintf(fd, "[%s] %s %sAPI\n", SUCC, "Hooked", "Crypto");
		break;

	case DLL_PROCESS_DETACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		_DD(&(PVOID&)_REP(Old, Encrypt), _REP(New, Encrypt));
		_DD(&(PVOID&)_REP(Old, Decrypt), _REP(New, Decrypt));
		_DD(&(PVOID&)_REP_3(New, CryptAcquire, Context), _REP_3(Old, CryptAcquire, Context));
		_DD(&(PVOID&)_REP(Old, SetKeyParam), _REP(New, SetKeyParam));
		_DD(&(PVOID&)_REP(Old, CreateHash), _REP(New, CreateHash));
		_DD(&(PVOID&)_REP(Old, HashData), _REP(New, HashData));
		_DD(&(PVOID&)_REP(Old, DeriveKey), _REP(New, DeriveKey));
		_DD(&(PVOID&)_REP(Old, GenKey), _REP(New, GenKey));
		_DD(&(PVOID&)_REP(Old, ImportKey), _REP(New, ImportKey));
		_DD(&(PVOID&)_REP(Old, ExportKey), _REP(New, ExportKey));
		_DD(&(PVOID&)_REP(Old, GenRandom), _REP(New, GenRandom));
		_DD(&(PVOID&)OldOpenFile, NewOpenFile);
		_DD(&(PVOID&)OldNtOpenFile, NewNtOpenFile);
		_DD(&(PVOID&)OldCreateFile, NewCreateFile);
		_DD(&(PVOID&)OldNtCreateFile, NewNtCreateFile);
		_DD(&(PVOID&)OldBCryEnc, NewBCryptEncrypt);

		DetourTransactionCommit();
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;
	}

	fclose(fd);
	return TRUE;
}

unsigned char* memorySearch(char* sg, char sge, size_t sgs) {
	unsigned char* sg_addr = NULL;

	DWORD pd = GetCurrentProcessId();
	HANDLE prcs = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pd);

	MEMORY_BASIC_INFORMATION nf;
	DWORD byteRead = 0;
	char* pbuf = NULL;
	unsigned char* cur = NULL;
	for (cur = NULL; VirtualQueryEx(prcs, cur, &nf, sizeof(nf)) == sizeof(nf); cur += nf.RegionSize) {

		if (nf.State == MEM_COMMIT && (nf.Type == MEM_MAPPED || nf.Type == MEM_PRIVATE || nf.Type == MEM_IMAGE) &&
			(nf.AllocationProtect == PAGE_EXECUTE || nf.AllocationProtect == PAGE_EXECUTE_READ || nf.AllocationProtect == PAGE_EXECUTE_READWRITE || nf.AllocationProtect == PAGE_EXECUTE_WRITECOPY))
		{
			pbuf = (char*)malloc(nf.RegionSize);
			ReadProcessMemory(prcs, cur, pbuf, nf.RegionSize, &byteRead);
			size_t mo = arraySearch(sg, sge, sgs, pbuf, byteRead, 31);
			if (mo != NULL) {
				sg_addr = cur + mo;
				break;
			}

		}
	}

	return sg_addr;
}

size_t arraySearch(char* ndle, char ndle_end, size_t ndle_size, char* hays, size_t hays_size, size_t thress) {
	size_t mo = NULL;
	for (int i = 0; i + ndle_size <= hays_size; i++) {
		size_t mat_count = 0;
		for (int j = 0; j < ndle_size; j++) {
			char ndleCompare = ndle[j];
			if (j == ndle_size - 1) {
				ndleCompare = ndle_end;
			}
			if (hays[i + j] == ndleCompare) {
				mat_count++;
			}
		}

		if (mat_count >= thress) {
			mo = i;
			break;
		}
	}

	return mo;
}

const std::string cTime() {
	SYSTEMTIME t;
	GetSystemTime(&t);
	char cTime[100] = "";
	sprintf(cTime, "%d:%d:%d %d", t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
	return std::string(cTime);
}

void MHE(LPTSTR psz, int nErrorNumber) {
	_ftprintf(stderr, TEXT("Program error. \n"));
	_ftprintf(stderr, TEXT("%s\n"), psz);
	_ftprintf(stderr, TEXT("Error number %x.\n"), nErrorNumber);
}

