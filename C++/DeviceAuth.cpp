#include "DeviceAuth.h"					// TODO: Rewrite according to the directory hierarchy

//==========================================================================================================================
// *** Title ***
// Microsoft Visual C++ 2022
// For Win32 applications only
// Device Authentication Class.
// *** File ***
// DeviceAuth.h: Header File.
// DeviceAuth.cpp: Source File.
// *** Class ***
// CDeviceAuthManager: Connect to WMI to obtain device information.
// CHardwareAuth: Authenticate hardware devices.
// CSoftwareAuth: Hardware-independent device authentication.
// *** Summary ***
// This class supports authentication by obtaining the serial numbers of devices and systems such as Windows via WMI.
// This allows applications to be restricted from launching or restricting functionality outside of certain environments.
// *** Notes ***
// 1. Platforms other than Windows are not supported.
// 2. It cannot be used on Windows, even on Windows 98 or earlier.
// 3. Non-Unicode environments are not supported.
// 4. It may or may not work properly in environments where WMI is disabled.
// 5. If parts are replaced for repair or other reasons, authentication may fail.
// 6. Some devices may not function properly with the authentication method.
// 7. Some WMI classes may be discontinued in the future.
// *** Update History ***
// August 12, 2023: Created
// September 16, 2025: Replace deprecated functions
//==========================================================================================================================

BOOL CDeviceAuthManager::GetClassObject(LPCWSTR lpClassName, IEnumWbemClassObject*& lpEnumerator, LPCWSTR lpWhereQuery = L"")
{
	IWbemClassObject* lpObj = NULL;
	ULONG uResult = 0;
	WCHAR lpQuery[MAX_LOADSTRING] = { 0 };
	size_t whereQuerySize;

	// Failed.
	if (FAILED(StringCchLength(lpWhereQuery, STRSAFE_MAX_CCH, &whereQuerySize)))
	{
		return FALSE;
	}

	if (whereQuerySize == 0)
	{
		StringCchPrintf(lpQuery, MAX_LOADSTRING, WQUERY_BASIC, lpClassName);
	}
	else
	{
		StringCchPrintf(lpQuery, MAX_LOADSTRING, WQUERY_WHERE, lpClassName, lpWhereQuery);
	}

	hRes = lpServices->ExecQuery(
		(BSTR)WQUERY_LANGUAGE,
		lpQuery,
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&lpEnumerator
	);

	if (FAILED(hRes))
	{
		lpServices->Release();
		lpLoc->Release();
		CoUninitialize();
		return FALSE;
	}

	return TRUE;
}
BOOL CDeviceAuthManager::ConnectSetup()
{
	lpLoc = NULL;
	lpServices = NULL;

	hRes = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	hRes = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE,
		NULL
	);

	// Failed.
	if (FAILED(hRes))
	{
		return FALSE;
	}

	hRes = CoCreateInstance(
		CLSID_WbemLocator,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		(LPVOID*)&lpLoc
	);

	if (FAILED(hRes))
	{
		CoUninitialize();
		return FALSE;
	}

	hRes = lpLoc->ConnectServer(
		(BSTR)WPATH_CIMV2,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		&lpServices
	);

	if (FAILED(hRes))
	{
		lpLoc->Release();
		CoUninitialize();
		return FALSE;
	}

	hRes = CoSetProxyBlanket(
		lpServices,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHN_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE
	);

	if (FAILED(hRes))
	{
		lpServices->Release();
		lpLoc->Release();
		CoUninitialize();
		return FALSE;
	}

	return TRUE;
}
VOID CDeviceAuthManager::DisconnectWMI()
{
	if (lpLoc != NULL)
	{
		lpLoc->Release();
	}

	if (lpServices != NULL)
	{
		lpServices->Release();
	}

	CoUninitialize();
}
CDeviceAuthManager::CDeviceAuthManager()
{
	ConnectSetup();
}
CDeviceAuthManager::~CDeviceAuthManager()
{
	DisconnectWMI();
}
BOOL CHardwareAuth::AuthComputerSerialNumber(BOOL& bResult, int iCount, ...)
{
	bResult = FALSE;
	IEnumWbemClassObject* lpEnumerator = NULL;
	if (GetClassObject(WCLASS_BIOS, lpEnumerator))
	{
		IWbemClassObject* lpObj = NULL;
		ULONG uResult = 0;
		while (lpEnumerator->Next(WBEM_INFINITE, 1, &lpObj, &uResult) == S_OK)
		{
			VARIANT vtProp;
			VariantInit(&vtProp);
			if (lpObj->Get(WPROP_SERIALNUMBER, NULL, &vtProp, NULL, NULL) == NO_ERROR)
			{
				va_list args;
				va_start(args, iCount);
				LPCWSTR lpValue;

				for (int i = 0; i < iCount; i++)
				{
					lpValue = va_arg(args, LPCWSTR);
					if (wcscmp(lpValue, vtProp.bstrVal) == 0)
					{
						bResult = TRUE;
						break;
					}
				}
				va_end(args);
			}

			VariantClear(&vtProp);
			lpObj->Release();
		}
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}

BOOL CHardwareAuth::AuthBaseBoardSerialNumber(BOOL& bResult, int iCount, ...)
{
	bResult = FALSE;
	IEnumWbemClassObject* lpEnumerator = NULL;
	if (GetClassObject(WCLASS_BASEBOARD, lpEnumerator))
	{
		IWbemClassObject* lpObj = NULL;
		ULONG uResult = 0;
		while (lpEnumerator->Next(WBEM_INFINITE, 1, &lpObj, &uResult) == S_OK)
		{
			VARIANT vtProp;
			VariantInit(&vtProp);
			if (lpObj->Get(WPROP_SERIALNUMBER, NULL, &vtProp, NULL, NULL) == NO_ERROR)
			{
				va_list args;
				va_start(args, iCount);
				LPCWSTR lpValue;

				for (int i = 0; i < iCount; i++)
				{
					lpValue = va_arg(args, LPCWSTR);
					if (wcscmp(lpValue, vtProp.bstrVal) == 0)
					{
						bResult = TRUE;
						break;
					}
				}
				va_end(args);
			}

			VariantClear(&vtProp);
			lpObj->Release();
		}
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}

BOOL CHardwareAuth::AuthSystemDisk(BOOL& bResult, int iCount, ...)
{
	bResult = FALSE;
	IEnumWbemClassObject* lpEnumerator = NULL;
	WCHAR lpWhere[MAX_LOADSTRING] = { 0 };

	StringCchPrintf(lpWhere, MAX_LOADSTRING, WFORMULA_MATCH, WPROP_INTERFACE, WPROPVAL_IDE);
	if (GetClassObject(WCLASS_DISK, lpEnumerator, lpWhere))
	{
		IWbemClassObject* lpObj = NULL;
		ULONG uResult = 0;
		while (lpEnumerator->Next(WBEM_INFINITE, 1, &lpObj, &uResult) == S_OK)
		{
			VARIANT vtProp;
			VariantInit(&vtProp);
			if (lpObj->Get(WPROP_SERIALNUMBER, NULL, &vtProp, NULL, NULL) == NO_ERROR)
			{
				va_list args;
				va_start(args, iCount);
				LPCWSTR lpValue;

				for (int i = 0; i < iCount; i++)
				{
					lpValue = va_arg(args, LPCWSTR);
					if (wcscmp(lpValue, vtProp.bstrVal) == 0)
					{
						bResult = TRUE;
						break;
					}
				}
				va_end(args);
			}

			VariantClear(&vtProp);
			lpObj->Release();
		}
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}
BOOL CHardwareAuth::AuthSystemDiskEx(BOOL& bResult, int iCount, ...)
{
	bResult = FALSE;
	IEnumWbemClassObject* lpEnumerator = NULL;
	WCHAR lpWhere[MAX_LOADSTRING] = { 0 };

	StringCchPrintf(lpWhere, MAX_LOADSTRING, WFORMULA_MATCH, WPROP_INTERFACE, WPROPVAL_IDE);
	if (GetClassObject(WCLASS_DISK, lpEnumerator, lpWhere))
	{
		IWbemClassObject* lpObj = NULL;
		ULONG uResult = 0;
		while (lpEnumerator->Next(WBEM_INFINITE, 1, &lpObj, &uResult) == S_OK)
		{
			VARIANT vtProp;
			VariantInit(&vtProp);
			if (lpObj->Get(WPROP_PNPDEVICEID, NULL, &vtProp, NULL, NULL) == NO_ERROR)
			{
				va_list args;
				va_start(args, iCount);
				LPCWSTR lpValue;

				for (int i = 0; i < iCount; i++)
				{
					lpValue = va_arg(args, LPCWSTR);
					if (wcscmp(lpValue, vtProp.bstrVal) == 0)
					{
						bResult = TRUE;
						break;
					}
				}
				va_end(args);
			}

			VariantClear(&vtProp);
			lpObj->Release();
		}
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}
BOOL CHardwareAuth::AuthExternalDisk(BOOL& bResult, int iCount, ...)
{
	bResult = FALSE;
	IEnumWbemClassObject* lpEnumerator = NULL;
	WCHAR lpWhere[MAX_LOADSTRING] = { 0 };

	StringCchPrintf(lpWhere, MAX_LOADSTRING, WFORMULA_MISSMATCH, WPROP_INTERFACE, WPROPVAL_IDE);
	if (GetClassObject(WCLASS_DISK, lpEnumerator, lpWhere))
	{
		IWbemClassObject* lpObj = NULL;
		ULONG uResult = 0;
		while (lpEnumerator->Next(WBEM_INFINITE, 1, &lpObj, &uResult) == S_OK)
		{
			VARIANT vtProp;
			VariantInit(&vtProp);
			if (lpObj->Get(WPROP_SERIALNUMBER, NULL, &vtProp, NULL, NULL) == NO_ERROR)
			{
				va_list args;
				va_start(args, iCount);
				LPCWSTR lpValue;

				for (int i = 0; i < iCount; i++)
				{
					lpValue = va_arg(args, LPCWSTR);
					if (wcscmp(lpValue, vtProp.bstrVal) == 0)
					{
						bResult = TRUE;
						break;
					}
				}
				va_end(args);
			}

			VariantClear(&vtProp);
			lpObj->Release();
		}
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}
BOOL CHardwareAuth::AuthExternalDiskEx(BOOL& bResult, int iCount, ...)
{
	bResult = FALSE;
	IEnumWbemClassObject* lpEnumerator = NULL;
	WCHAR lpWhere[MAX_LOADSTRING] = { 0 };

	StringCchPrintf(lpWhere, MAX_LOADSTRING, WFORMULA_MISSMATCH, WPROP_INTERFACE, WPROPVAL_IDE);
	if (GetClassObject(WCLASS_DISK, lpEnumerator, lpWhere))
	{
		IWbemClassObject* lpObj = NULL;
		ULONG uResult = 0;
		while (lpEnumerator->Next(WBEM_INFINITE, 1, &lpObj, &uResult) == S_OK)
		{
			VARIANT vtProp;
			VariantInit(&vtProp);
			if (lpObj->Get(WPROP_PNPDEVICEID, NULL, &vtProp, NULL, NULL) == NO_ERROR)
			{
				va_list args;
				va_start(args, iCount);
				LPCWSTR lpValue;

				for (int i = 0; i < iCount; i++)
				{
					lpValue = va_arg(args, LPCWSTR);
					if (wcscmp(lpValue, vtProp.bstrVal) == 0)
					{
						bResult = TRUE;
						break;
					}
				}
				va_end(args);
			}

			VariantClear(&vtProp);
			lpObj->Release();
		}
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}
BOOL CSoftwareAuth::AuthWindowsSerialNumber(BOOL& bResult, int iCount, ...)
{
	bResult = FALSE;
	IEnumWbemClassObject* lpEnumerator = NULL;
	if (GetClassObject(WCLASS_OS, lpEnumerator))
	{
		IWbemClassObject* lpObj = NULL;
		ULONG uResult = 0;
		while (lpEnumerator->Next(WBEM_INFINITE, 1, &lpObj, &uResult) == S_OK)
		{
			VARIANT vtProp;
			VariantInit(&vtProp);
			if (lpObj->Get(WPROP_SERIALNUMBER, NULL, &vtProp, NULL, NULL) == NO_ERROR)
			{
				va_list args;
				va_start(args, iCount);
				LPCWSTR lpValue;

				for (int i = 0; i < iCount; i++)
				{
					lpValue = va_arg(args, LPCWSTR);
					if (lstrcmp(lpValue, vtProp.bstrVal) == 0)
					{
						bResult = TRUE;
						break;
					}
				}
				va_end(args);
			}

			VariantClear(&vtProp);
			lpObj->Release();
		}
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}
BOOL CSoftwareAuth::AuthUserAccountSID(BOOL& bResult, int iCount, ...)
{
	bResult = FALSE;

	LPWSTR lpSidBuf;
	WCHAR lpUser[MAX_LOADSTRING];
	WCHAR lpDomain[MAX_LOADSTRING];
	BYTE szSidBuf[MAX_LOADSTRING];

	DWORD dUserSize = sizeof(lpUser) / sizeof(WCHAR);
	DWORD dDomainSize = sizeof(lpDomain) / sizeof(WCHAR);
	DWORD dSidSize = sizeof(szSidBuf);

	PSID lpSid = (PSID)szSidBuf;
	SID_NAME_USE SidUserName;

	ZeroMemory(lpUser, dUserSize);
	ZeroMemory(lpDomain, dDomainSize);
	memset(szSidBuf, 0, sizeof(szSidBuf));

	if (!GetUserName(lpUser, &dUserSize))
	{
		return FALSE;
	}

	if (!LookupAccountName(NULL, lpUser, lpSid, &dSidSize, lpDomain, &dDomainSize, &SidUserName))
	{
		return FALSE;
	}

	if (!ConvertSidToStringSid(lpSid, &lpSidBuf))
	{
		return FALSE;
	}

	va_list args;
	va_start(args, iCount);
	LPCWSTR lpValue;
	for (int i = 0; i < iCount; i++)
	{
		lpValue = va_arg(args, LPCWSTR);
		if (wcscmp(lpValue, lpSidBuf) == 0)
		{
			bResult = TRUE;
			break;
		}
	}

	va_end(args);
	LocalFree(lpSidBuf);

	return TRUE;
}
BOOL CSoftwareAuth::AuthUserAccount(LPCWSTR lpUser, LPCWSTR lpDomain, LPCWSTR lpPassword, HANDLE& hToken)
{
	return LogonUser(lpUser, lpDomain, lpPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken);
}
BOOL CSoftwareAuth::AuthUserAccount(LPCWSTR lpUser, LPCWSTR lpDomain, LPCWSTR lpPassword)
{
	HANDLE hToken = NULL;
	BOOL bResult = AuthUserAccount(lpUser, lpDomain, lpPassword, hToken);
	CloseHandle(hToken);

	return bResult;
}