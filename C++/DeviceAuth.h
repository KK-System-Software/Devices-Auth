#pragma once

#include <Windows.h>
#include <strsafe.h>
#include <string>
#include <string_view>
#include <initializer_list>

#define _WIN32_DCOM
#include <comdef.h>
#include <WbemIdl.h>
#include <sddl.h>
#pragma comment(lib, "wbemuuid.lib")

#define WPATH_CIMV2							L"root\\CIMV2"

#define WQUERY_LANGUAGE						L"WQL"
#define WQUERY_BASIC						L"SELECT * FROM %s"
#define WQUERY_WHERE						L"SELECT * FROM %s WHERE %s"

#define WCLASS_BIOS							L"Win32_BIOS"
#define WCLASS_BASEBOARD					L"Win32_BaseBoard"
#define WCLASS_DISK							L"Win32_DiskDrive"
#define WCLASS_OS							L"Win32_OperatingSystem"

#define WPROP_INTERFACE						L"InterfaceType"
#define WPROP_PNPDEVICEID					L"PNPDeviceID"
#define WPROP_SERIALNUMBER					L"SerialNumber"

#define WPROPVAL_IDE						L"IDE"
#define WFORMULA_MATCH						L"%s = '%s'"
#define WFORMULA_MISSMATCH					L"%s <> '%s'"

#define MAX_QUERY							MAXBYTE
#define MAX_USERSID							MAXBYTE
#define MAX_USER							MAXBYTE

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

#if !UNICODE
#error Not supported in non-Unicode environments.
#endif

using namespace std;

// Class that defines functions used in the CHardwareAuth classes and CSoftwareAuth classes.
class CDeviceAuthManager
{
private:
	HRESULT hRes;
	IWbemLocator* lpLoc;
	IWbemServices* lpServices;
protected:
	BOOL GetClassObject(LPCWSTR lpClassName, IEnumWbemClassObject*& lpEnumerator, LPCWSTR lpWhereQuery);
	BOOL ConnectSetup();
	VOID DisconnectWMI();
	CDeviceAuthManager();
	~CDeviceAuthManager();
	BOOL VerifySerialNumber(initializer_list<wstring_view> serialNumbers, LPCWSTR lpWMIClass, LPCWSTR lpWMIProperty,
		BOOL bWhereQuery, BOOL bEqual, LPCWSTR lpWhereLeftSide, LPCWSTR lpWhereRightSide);
};

/// Authentication is performed in a way that depends on the specific hardware, such as motherboard, HDD/SSD, etc.
/// If parts are replaced for repair or other reasons, authentication may fail.
class CHardwareAuth : CDeviceAuthManager
{
public:
	// The serial number of the PC is used to authenticate.
	// The serial number is tied to the BIOS firmware.
	// It is different from the motherboard serial number.
	BOOL AuthComputerSerialNumber(initializer_list<wstring_view> serialNumbers);

	// Authenticate by motherboard serial number.
	// This is different from the serial number tied to the firmware in the BIOS.
	BOOL AuthBaseBoardSerialNumber(initializer_list<wstring_view> serialNumbers);

	// Authentication is performed by the serial number of the system drive.
	// Usually the drive is internal and the connection method is SATA, mSATA, or M.2.
	BOOL AuthSystemDisk(initializer_list<wstring_view> serialNumbers);

	// Authentication is performed by the device instance path of the system drive.
	// Usually the drive is internal and the connection method is SATA, mSATA, or M.2.
	// * The device instance path can be found in the device manager properties.
	BOOL AuthSystemDiskEx(initializer_list<wstring_view> serialNumbers);

	// Authentication is done by the serial number of the external disk.
	// targets are USB memory, external HDD/SSD, and SCSI (UAS)-connected HDD/SSD.
	BOOL AuthExternalDisk(initializer_list<wstring_view> serialNumbers);

	// Authentication is done by the device instance path of the external disk.
	// targets are USB memory, external HDD/SSD, and SCSI (UAS)-connected HDD/SSD.
	// * The device instance path can be found in the device manager properties.
	BOOL AuthExternalDiskEx(initializer_list<wstring_view> serialNumbers);
};

// Authentication is performed in a manner that does not depend on a specific device, such as a Windows serial ID.
class CSoftwareAuth : CDeviceAuthManager
{
public:
	// Authentication is performed using the product ID assigned to each Windows license.
	// The product ID can be found in the Control Panel under "System" or "System" and "Details" under "Settings".
	BOOL AuthWindowsSerialNumber(initializer_list<wstring_view> serialNumbers);

	/// Authenticate with the SID of the currently logged in user account.
	/// The SID is a unique identification number given to Windows user accounts and user groups.
	BOOL AuthUserAccountSID(initializer_list<wstring_view> serialNumbers);

	// Authenticate with the user name, domain name and password of the user account.
	// If authentication is successful, you receive a handle to the authenticated user's token.
	// * This function is a wrapper function for LogonUser in the Win32 API.
	BOOL AuthUserAccount(LPCWSTR lpUser, LPCWSTR lpDomain, LPCWSTR lpPassword, HANDLE& hToken);

	// Authenticate with the user name, domain name and password of the user account.
	// This function internally calls the LogonUser function in the Win32 API.
	BOOL AuthUserAccount(LPCWSTR lpUser, LPCWSTR lpDomain, LPCWSTR lpPassword);
};