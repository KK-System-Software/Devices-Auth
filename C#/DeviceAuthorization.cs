using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;

//==========================================================================================================================
// *** Summary ***
// This class supports authentication by obtaining the serial numbers of devices and systems such as Windows via WMI.
// This allows applications to be restricted from launching or restricting functionality outside of certain environments.
// *** Notes ***
// 1. Platforms other than Windows are not supported.
// 2. "System.Management.dll" must be checked in the reference settings to use this class.
// 3. It may or may not work properly in environments where WMI is disabled.
// 4. If parts are replaced for repair or other reasons, authentication may fail.
// 5. Some devices may not function properly with the authentication method.
// 6. Some WMI classes may be discontinued in the future.
//==========================================================================================================================

/// <summary>
/// <para>Class that defines constants used in the HardwareAuthentication classes and SoftwareAuthentication classes.</para>
/// </summary>
public abstract class AuthenticationManager
{
    public const string TXT_EXCEPTION1 = "None of the serial numbers required for authentication have been specified.";
    public const string TXT_EXCEPTION2 = "An empty string or null cannot be specified for the MAC address to be authenticated.";
    public const string TXT_EXCEPTION3 = "None of the SID required for authentication have been specified.";
    public const string WMICLASS_BIOS = "Win32_BIOS";
    public const string WMICLASS_BASEBOARD = "Win32_BaseBoard";
    public const string WMICLASS_DISK = "Win32_DiskDrive";
    public const string WMICLASS_OS = "Win32_OperatingSystem";
    public const string WMIPROP_SERIALNUMBER = "SerialNumber";
    public const string WMIPROP_PNPDEVICEID = "PNPDeviceID";
    public const string WMIPROP_INTERFACE = "InterfaceType";
    public const string PROPVALUE_IDE = "IDE";
    public const string DLLNAME_ADVAPI32 = "advapi32.dll";
    public const string CHAR_HYPHEN = "-";

    /// <summary>
    /// Access WMI to obtain the necessary data.
    /// </summary>
    /// <param name="path"><para>Class name of the WMI from which to retrieve data.</para>
    /// <para>Class name starting with CIM_ or Win32_.</para></param>
    /// <returns>ManagementObjects collection.</returns>
    protected ManagementObjectCollection GetWMIObject(string path)
    {
        ManagementObjectCollection mo;
        using (ManagementClass mc = new ManagementClass(path))
        {
            mo = mc.GetInstances();
        }

        return mo;
    }

    /// <summary>
    /// Inspects the value of the parameter and throws an "ArgumentException" if it is null or empty.
    /// </summary>
    /// <param name="param">Parameters to be inspected. Only arrays of strings are supported.</param>
    /// <param name="errorText">Exception message. Can be omitted.</param>
    /// <exception cref="ArgumentException"></exception>
    protected void CheckStringNull(string[] param, string errorText = "")
    {
        if (param == null || param.Length == 0)
        {
            throw new ArgumentException(errorText);
        }
    }
}

/// <summary>
/// <para>Authentication is performed in a way that depends on the specific hardware, such as motherboard, HDD/SSD, etc.</para>
/// <para>If parts are replaced for repair or other reasons, authentication may fail.</para>
/// </summary>
public class HardwareAuthentication : AuthenticationManager
{
    /// <summary>
    /// <para>The serial number of the PC is used to authenticate.</para>
    /// <para>The serial number is tied to the BIOS firmware.</para>
    /// <para>It is different from the motherboard serial number.</para>
    /// </summary>
    /// <param name="serialNumbers"><para>Serial number to be authenticated.</para>
    /// <para>*The format of the serial number varies from manufacturer to manufacturer.</para></param>
    /// <returns>Success or failure of authentication.</returns>
    /// <exception cref="ArgumentException">None of the serial numbers required for authentication have been specified.</exception>
    public bool AuthComputerSerialNumber(params string[] serialNumbers)
    {
        CheckStringNull(serialNumbers, TXT_EXCEPTION1);
        using (ManagementObjectCollection moc = GetWMIObject(WMICLASS_BIOS))
        {
            foreach (ManagementObject mo in moc)
            {
                foreach (string serialNumber in serialNumbers)
                {
                    if (serialNumber == (string)mo[WMIPROP_SERIALNUMBER])
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /// <summary>
    /// <para>Authenticate by motherboard serial number.</para>
    /// <para>This is different from the serial number tied to the firmware in the BIOS.</para>
    /// </summary>
    /// <param name="serialNumbers"><para>Serial number to be authenticated.</para>
    /// <para>*The format of the serial number varies from manufacturer to manufacturer in mothermoard.</para></param>
    /// <returns>Success or failure of authentication.</returns>
    /// <exception cref="ArgumentException">None of the serial numbers required for authentication have been specified.</exception>
    public bool AuthBaseBoardSerialNumber(params string[] serialNumbers)
    {
        CheckStringNull(serialNumbers, TXT_EXCEPTION1);
        using (ManagementObjectCollection moc = GetWMIObject(WMICLASS_BASEBOARD))
        {
            foreach (ManagementObject mo in moc)
            {
                foreach (string serialNumber in serialNumbers)
                {
                    if (serialNumber == (string)mo[WMIPROP_SERIALNUMBER])
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /// <summary>
    /// <para>Authentication is performed by the serial number of the system drive.</para>
    /// <para>Usually the drive is internal and the connection method is SATA, mSATA, or M.2.</para>
    /// </summary>
    /// <param name="serialNumbers">Serial number to be authenticated.</param>
    /// <returns>Success or failure of authentication.</returns>
    /// <exception cref="ArgumentException">None of the serial numbers required for authentication have been specified.</exception>
    public bool AuthSystemDisk(params string[] serialNumbers)
    {
        CheckStringNull(serialNumbers, TXT_EXCEPTION1);
        using (ManagementObjectCollection moc = GetWMIObject(WMICLASS_DISK))
        {
            foreach (ManagementObject mo in moc)
            {
                if ((string)mo[WMIPROP_INTERFACE] == PROPVALUE_IDE)
                {
                    foreach (string serialNumber in serialNumbers)
                    {
                        if (serialNumber == (string)mo[WMIPROP_SERIALNUMBER])
                        {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    /// <summary>
    /// <para>Authentication is performed by the device instance path of the system drive.</para>
    /// <para>Usually the drive is internal and the connection method is SATA, mSATA, or M.2.</para>
    /// <para>*The device instance path can be found in the device manager properties.</para>
    /// </summary>
    /// <param name="instancePaths">Device instance path to be authenticated.</param>
    /// <returns>Success or failure of authentication.</returns>
    /// <exception cref="ArgumentException">None of the device instance path required for authentication have been specified.</exception>
    public bool AuthSystemDiskEx(params string[] instancePaths)
    {
        CheckStringNull(instancePaths, TXT_EXCEPTION1);
        using (ManagementObjectCollection moc = GetWMIObject(WMICLASS_DISK))
        {
            foreach (ManagementObject mo in moc)
            {
                if ((string)mo[WMIPROP_INTERFACE] == PROPVALUE_IDE)
                {
                    foreach (string instancePath in instancePaths)
                    {
                        if (instancePath == (string)mo[WMIPROP_PNPDEVICEID])
                        {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    /// <summary>
    /// <para>Authentication is done by the serial number of the external disk.</para>
    /// <para>targets are USB memory, external HDD/SSD, and SCSI (UAS)-connected HDD/SSD.</para>
    /// </summary>
    /// <param name="serialNumbers">Serial number to be authenticated.</param>
    /// <returns>Success or failure of authentication.</returns>
    /// <exception cref="ArgumentException">None of the serial numbers required for authentication have been specified.</exception>
    public bool AuthExternalDisk(params string[] serialNumbers)
    {
        CheckStringNull(serialNumbers, TXT_EXCEPTION1);
        using (ManagementObjectCollection moc = GetWMIObject(WMICLASS_DISK))
        {
            foreach (ManagementObject mo in moc)
            {
                foreach (string serialNumber in serialNumbers)
                {
                    if ((string)mo[WMIPROP_INTERFACE] != PROPVALUE_IDE
                                            && serialNumber == (string)mo[WMIPROP_SERIALNUMBER])
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /// <summary>
    /// <para>Authentication is done by the device instance path of the external disk.</para>
    /// <para>targets are USB memory, external HDD/SSD, and SCSI (UAS)-connected HDD/SSD.</para>
    /// <para>*The device instance path can be found in the device manager properties.</para>
    /// </summary>
    /// <param name="instancePaths">Device instance path to be authenticated.</param>
    /// <returns>Success or failure of authentication.</returns>
    /// <exception cref="ArgumentException">None of the device instance path required for authentication have been specified.</exception>
    public bool AuthExternalDiskEx(params string[] instancePaths)
    {
        CheckStringNull(instancePaths, TXT_EXCEPTION1);
        using (ManagementObjectCollection moc = GetWMIObject(WMICLASS_DISK))
        {
            foreach (ManagementObject mo in moc)
            {
                foreach (string instancePath in instancePaths)
                {
                    if ((string)mo[WMIPROP_INTERFACE] != PROPVALUE_IDE
                                           && instancePath == (string)mo[WMIPROP_PNPDEVICEID])
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /// <summary>
    /// <para>Authentication is based on MAC address.</para>
    /// <para>If the MAC address cannot be obtained, authentication is considered to have failed.</para>
    /// </summary>
    /// <param name="address"><para>MAC address to be authenticated.</para>
    /// <para>A 12-digit hexadecimal number without hyphens.</para></param>
    /// <param name="isError"><para>True is returned only if an error occurs in obtaining the MAC address. Otherwise, false.</para></param>
    /// <param name="loopback"><para>Whether to include loopback addresses in the scope. Default is false.</para></param>
    /// <returns><para>Success or failure of authentication.</para>
    /// <para>*Always fails (false) in case of error.</para></returns>
    /// <exception cref="ArgumentException">An empty string or null cannot be specified for the MAC address to be authenticated.</exception>
    public bool AuthEthernetAddress(string address, out bool isError, bool loopback = false)
    {
        isError = false;

        if (address == null || address.Length == 0)
        {
            throw new ArgumentException(TXT_EXCEPTION2);
        }

        List<PhysicalAddress> list = GetEthernetAddress(loopback);
        if (list == null)
        {
            isError = true;
            return false;
        }

        foreach (PhysicalAddress pa in list)
        {
            if (address == pa.ToString())
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// <para>Obtains the MAC address.</para>
    /// <para>*This function cannot be used from an external class.</para>
    /// </summary>
    /// <param name="loopback"><para>Whether to include loopback addresses in the scope. Default is false.</para></param>
    /// <returns>A list-type variable in which MAC addresses are stored.</returns>
    private List<PhysicalAddress> GetEthernetAddress(bool loopback = false)
    {
        List<PhysicalAddress> result = new List<PhysicalAddress>();

        try
        {
            NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface intf in interfaces)
            {
                if (intf.OperationalStatus != OperationalStatus.Up)
                {
                    continue;
                }

                if (intf.NetworkInterfaceType == NetworkInterfaceType.Unknown)
                {
                    continue;
                }

                if (loopback == false && intf.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                {
                    continue;
                }

                result.Add(intf.GetPhysicalAddress());

            }
        }
        catch
        {
            result = null;
        }

        return result;
    }
}

/// <summary>
/// Authentication is performed in a manner that does not depend on a specific device, such as a Windows serial ID.
/// </summary>
public class SoftwareAuthentication : AuthenticationManager
{
    [DllImport(DLLNAME_ADVAPI32, SetLastError = true, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LogonUser(
          [MarshalAs(UnmanagedType.LPStr)] string pszUserName,
          [MarshalAs(UnmanagedType.LPStr)] string pszDomain,
          [MarshalAs(UnmanagedType.LPStr)] string pszPassword,
          int dwLogonType,
          int dwLogonProvider,
          ref IntPtr phToken);

    /// <summary>
    /// <para>Type of hash function.</para>
    /// <para>This enumerator is used for authentication using hash values.</para>
    /// </summary>
    public enum Hash
    {
        MD5,
        SHA1,
        SHA256,
        SHA384,
        SHA512,
    }

    /// <summary>
    /// <para>Authentication is performed using the product ID assigned to each Windows license.</para>
    /// <para>The product ID can be found in the Control Panel under "System" or "System" and "Details" under "Settings".</para>
    /// </summary>
    /// <param name="serialNumbers">Product ID to be authenticated.</param>
    /// <returns>Success or failure of authentication.</returns>
    /// <exception cref="ArgumentException">None of the serial numbers required for authentication have been specified.</exception>
    public bool AuthWindowsSerialNumber(params string[] serialNumbers)
    {
        CheckStringNull(serialNumbers, TXT_EXCEPTION1);
        using (ManagementObjectCollection moc = GetWMIObject(WMICLASS_OS))
        {
            foreach (ManagementObject mo in moc)
            {
                foreach (string serialNumber in serialNumbers)
                {
                    if (serialNumber == (string)mo[WMIPROP_SERIALNUMBER])
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /// <summary>
    /// <para>Authenticate with the SID of the currently logged in user account.</para>
    /// <para>The SID is a unique identification number given to Windows user accounts and user groups.</para>
    /// </summary>
    /// <param name="strSID">SID to be authenticated.</param>
    /// <returns>Success or failure of authentication.</returns>
    /// <exception cref="ArgumentException">None of the SID required for authentication have been specified.</exception>
    public bool AuthUserAccountSID(params string[] strSID)
    {
        using (WindowsIdentity wi = WindowsIdentity.GetCurrent())
        {
            CheckStringNull(strSID, TXT_EXCEPTION3);
            foreach (string SID in strSID)
            {
                if (SID == wi.User.Value)
                {
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// <para>Authentication is performed with hash values obtained from the file. </para>
    /// <para>The hash functions supported are MD5, SHA1, SHA256, SHA384 and SHA512.</para>
    /// </summary>
    /// <param name="filePath">Path of the file used for authentication.</param>
    /// <param name="hash">Hash value of the file as success.</param>
    /// <param name="hashType">Type of hash function.</param>
    /// <returns>Success or failure of authentication.</returns>
    /// <exception cref="PathTooLongException">Path of a file that exceeds 256 characters.</exception>
    /// <exception cref="FileNotFoundException">Invalid file path.</exception>
    /// <exception cref="IOException">IO error.</exception>
    public bool AuthFileHash(string filePath, string hash, Hash hashType)
    {
        string hashValue;
        using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
        {
            byte[] b = null;
            switch (hashType)
            {
                case Hash.MD5:
                    b = MD5.Create().ComputeHash(fs);
                    break;
                case Hash.SHA1:
                    b = SHA1.Create().ComputeHash(fs);
                    break;
                case Hash.SHA256:
                    b = SHA256.Create().ComputeHash(fs);
                    break;
                case Hash.SHA384:
                    b = SHA384.Create().ComputeHash(fs);
                    break;
                case Hash.SHA512:
                    b = SHA512.Create().ComputeHash(fs);
                    break;
            } 
            hashValue = Convert.ToBase64String(b).ToLower().Replace(CHAR_HYPHEN, string.Empty);
        }

        return hashValue == hash;
    }

    /// <summary>
    /// <para>Authenticate with the user name, domain name and password of the user account.</para>
    /// <para>This method internally calls the LogonUser function in the Win32 API.</para>
    /// </summary>
    /// <param name="userName">username</param>
    /// <param name="domainName">The name of the domain to which the user belongs. If not, null. Empty characters allowed.</param>
    /// <param name="password">The plaintext password. They are case sensitive.</param>
    /// <returns>Success or failure of authentication.</returns>
    public bool AuthUserAccount(string userName, string domainName, string password)
    {
        IntPtr token = IntPtr.Zero;
        bool result = LogonUser(userName, domainName, password, 2, 0, ref token);
        return result;
    }

    /// <summary>
    /// <para>Authenticate with the user name, domain name and password of the user account.</para>
    /// <para>If authentication is successful, you receive a handle to the authenticated user's token.</para>
    /// <para>*This function is a wrapper function for LogonUser in the Win32 API.</para>
    /// </summary>
    /// <param name="userName">username</param>
    /// <param name="domainName">The name of the domain to which the user belongs. If not, null. Empty characters allowed.</param>
    /// <param name="password">The plaintext password. They are case sensitive.</param>
    /// <param name="token">The handle of the token. Upon successful authentication, the token handle for the authenticated user account is stored. NULL is stored if authentication fails.</param>
    /// <returns>Success or failure of authentication.</returns>
    public bool LogonUser(string userName, string domainName, string password, ref IntPtr token)
    {
        token = IntPtr.Zero;
        bool result = LogonUser(userName, domainName, password, 2, 0, ref token);
        return result;
    }
}