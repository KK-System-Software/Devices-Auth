// TODO: Rewrite according to the directory hierarchy
#include "DeviceAuth.h"

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
// 2. It cannot be used on except Windows, even on Windows 98 or earlier.
// 3. Non-Unicode environments are not supported.
// 4. Not available in environments prior to C++17.
// 5. It may or may not work properly in environments where WMI is disabled.
// 6. If parts are replaced for repair or other reasons, authentication may fail.
// 7. Some devices may not function properly with the authentication method.
// 8. Some WMI classes may be discontinued in the future.
// *** Update History ***
// August 12, 2023: Created
// September 16, 2025: Replace deprecated functions
// September 16, 2025: Changes to some function signatures and internal processing efficiency improvements.
//==========================================================================================================================

BOOL CDeviceAuthManager::GetClassObject(LPCWSTR lpClassName, IEnumWbemClassObject*& lpEnumerator, LPCWSTR lpWhereQuery = L"")
{
	IWbemClassObject* lpObj = NULL;
	ULONG uResult = 0;
	WCHAR lpQuery[MAX_QUERY] = { 0 };
	size_t whereQuerySize;

	// Failed.
	if (FAILED(StringCchLength(lpWhereQuery, STRSAFE_MAX_CCH, &whereQuerySize)))
	{
		return FALSE;
	}

	if (whereQuerySize == 0)
	{
		StringCchPrintf(lpQuery, MAX_QUERY, WQUERY_BASIC, lpClassName);
	}
	else
	{
		StringCchPrintf(lpQuery, MAX_QUERY, WQUERY_WHERE, lpClassName, lpWhereQuery);
	}

	hRes = lpServices->ExecQuery(
		(BSTR)WQUERY_LANGUAGE,
		lpQuery,
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&lpEnumerator
	);

	// Failed.
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

	// Failed.
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

	// Failed.
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

	// Failed.
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

BOOL CDeviceAuthManager::VerifySerialNumber(initializer_list<wstring_view> serialNumbers, LPCWSTR lpWMIClass, LPCWSTR lpWMIProperty,
	BOOL bWhereQuery = FALSE, BOOL bEqual = TRUE, LPCWSTR lpWhereLeftSide = L"", LPCWSTR lpWhereRightSide = L"")
{
	BOOL bResult = FALSE;
	IEnumWbemClassObject* lpEnumerator = NULL;
	WCHAR lpWhere[MAX_QUERY] = { 0 };

	if (bWhereQuery)
	{
		StringCchPrintf(lpWhere, MAX_QUERY, (bEqual ? WFORMULA_MATCH : WFORMULA_MISSMATCH), lpWhereLeftSide, lpWhereRightSide);
	}

	if (GetClassObject(lpWMIClass, lpEnumerator, (bWhereQuery ? lpWhere : L"")))
	{
		IWbemClassObject* lpObj = NULL;
		ULONG uResult = 0;
		while (lpEnumerator->Next(WBEM_INFINITE, 1, &lpObj, &uResult) == S_OK)
		{
			VARIANT vtProp;
			VariantInit(&vtProp);
			if (lpObj->Get(lpWMIProperty, NULL, &vtProp, NULL, NULL) == NO_ERROR)
			{
				std::wstring ws(vtProp.bstrVal ? vtProp.bstrVal : L"");
				for (auto candidate : serialNumbers) {
					if (ws == candidate) {
						bResult = TRUE;
						break;
					}
				}
			}

			VariantClear(&vtProp);
			lpObj->Release();
		}
	}
	else
	{
		return FALSE;
	}

	return bResult;
}

BOOL CHardwareAuth::AuthComputerSerialNumber(initializer_list<wstring_view> serialNumbers)
{
	return VerifySerialNumber(serialNumbers, WCLASS_BIOS, WPROP_SERIALNUMBER);
}

BOOL CHardwareAuth::AuthBaseBoardSerialNumber(initializer_list<wstring_view> serialNumbers)
{
	return VerifySerialNumber(serialNumbers, WCLASS_BASEBOARD, WPROP_SERIALNUMBER);
}

BOOL CHardwareAuth::AuthSystemDisk(initializer_list<wstring_view> serialNumbers)
{
	return VerifySerialNumber(serialNumbers, WCLASS_DISK, WPROP_SERIALNUMBER,
		TRUE, TRUE, WPROP_INTERFACE, WPROPVAL_IDE);
}

BOOL CHardwareAuth::AuthSystemDiskEx(initializer_list<wstring_view> serialNumbers)
{
	return VerifySerialNumber(serialNumbers, WCLASS_DISK, WPROP_PNPDEVICEID,
		TRUE, TRUE, WPROP_INTERFACE, WPROPVAL_IDE);
}

BOOL CHardwareAuth::AuthExternalDisk(initializer_list<wstring_view> serialNumbers)
{
	return VerifySerialNumber(serialNumbers, WCLASS_DISK, WPROP_SERIALNUMBER,
		TRUE, FALSE, WPROP_INTERFACE, WPROPVAL_IDE);
}

BOOL CHardwareAuth::AuthExternalDiskEx(initializer_list<wstring_view> serialNumbers)
{
	return VerifySerialNumber(serialNumbers, WCLASS_DISK, WPROP_PNPDEVICEID,
		TRUE, FALSE, WPROP_INTERFACE, WPROPVAL_IDE);
}

BOOL CSoftwareAuth::AuthWindowsSerialNumber(initializer_list<wstring_view> serialNumbers)
{
	return VerifySerialNumber(serialNumbers, WCLASS_OS, WPROP_SERIALNUMBER);
}

BOOL CSoftwareAuth::AuthUserAccountSID(initializer_list<wstring_view> serialNumbers)
{
	BOOL bResult = FALSE;

	LPWSTR lpSidBuf;
	WCHAR lpUser[MAX_USER];
	WCHAR lpDomain[MAX_USER];
	BYTE szSidBuf[MAX_USERSID];

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

	std::wstring ws;
	for (auto ws : serialNumbers)
	{
		if (ws == lpSidBuf)
		{
			bResult = TRUE;
			break;
		}
	}
	LocalFree(lpSidBuf);

	return bResult;
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