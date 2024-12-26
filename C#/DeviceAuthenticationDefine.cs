using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Runtime.Serialization.Formatters.Binary;
using System.Xml.Serialization;

//==========================================================================================================================
// *** Summary ***
// This class is a device authentication definition class that defines the device information required for device authentication.
// The defined device information can be read and written as a file.
// Reading resource files is also supported.
// *** Notes ***
// 1. The GUID of the application that uses device authentication is required to read and write the definition file.
// 2. The serial number required for device authentication can be found on the WMI.
//==========================================================================================================================

/// <summary>
/// It defines the data needed to authenticate the device.
/// </summary>
[Serializable()]
public class DeviceAuthenticationDefine
{
    /// <summary>
    /// A group of device classes registered in the device authentication definition.
    /// </summary>
    public List<Device> DeviceList { get; set; }

    /// <summary>
    /// Retrieve device information based on name.
    /// </summary>
    /// <param name="name">Name of the device to be acquired.</param>
    /// <returns>Class on the relevant device.</returns>
    public Device this[string name]
    {
        get
        {
            for (int i = 0; i <DeviceList.Count; i++)
            {
                if (name == DeviceList[i].Name)
                {
                    return DeviceList[i];
                }
            }

            return null;
        }
    }

    public DeviceAuthenticationDefine()
    {
        DeviceList = new List<Device>();
    }
}

/// <summary>
/// <para>Define device information.</para>
/// <para>The Name and SerialNumber properties are required.</para>
/// <para>Comment can be omitted.</para>
/// </summary>
[Serializable()]
public class Device
{
    /// <summary>
    /// <para>Defines the name of the device.</para>
    /// <para>This property is used primarily by the indexer of the Device class to obtain the serial number.</para>
    /// </summary>
    public string Name { get; set; }

    /// <summary>
    /// <para>An identification number assigned to identify a device.</para>
    /// <para>The format and number of digits of serial numbers vary by manufacturer.</para>
    /// </summary>
    public string SerialNumber { get; set; }

    /// <summary>
    /// <para>An identification number assigned to identify a device.</para>
    /// <para>It consists of the Vendor ID, Product ID, and Serial Number categories, each of which is separated by a slash.</para>
    /// </summary>
    public string DeviceInstancePath { get; set; }

    /// <summary>
    /// <para>Use it to supplement information about the device, such as in debugging.</para>
    /// <para>This property can be omitted.</para>
    /// </summary>
    public string Comment { get; set; }
}

/// <summary>
/// This class supports reading and writing device authentication definition classes.
/// </summary>
public static class DeviceAuthenticationDefineManagement
{
    private const int SIZE_KEY = 256;
    private const int SIZE_BLOCK = 128;
    private const int SIZE_BUFFER = 1024;
    private static AesCryptoServiceProvider _AES;

    /// <summary>
    /// Load the device authentication definition file.
    /// </summary>
    /// <param name="filePath">Path of the device authentication definition file.</param>
    /// <param name="guid">The guid of the application using the device authentication definition file.</param>
    /// <returns>If successful, an instance of the device authentication definition class is returned.</returns>
    public static DeviceAuthenticationDefine LoadFromFile(string filePath, string guid)
    {
        DeviceAuthenticationDefine result = null;
        using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
        {
            result = LoadFromStream(fs, guid);
        }

        return result;
    }

    /// <summary>
    /// <para>Loads a device authentication definition class from a binary.</para>
    /// <para>This method is primarily used to read device authentication definition files embedded in resource files.</para>
    /// </summary>
    /// <param name="binary">Binary to load device authentication definition class.</param>
    /// <param name="guid">The guid of the application using the device authentication definition class.</param>
    /// <returns></returns>
    public static DeviceAuthenticationDefine LoadFromBinary(byte[] binary, string guid)
    {
        DeviceAuthenticationDefine result = null;
        using (MemoryStream ms = new MemoryStream(binary))
        {
            result = LoadFromStream(ms, guid);
        }

        return result;
    }

    /// <summary>
    /// Reads the device authentication definition class from the stream.
    /// </summary>
    /// <param name="stream">Stream from which the binary of the device authentication definition file was read.</param>
    /// <param name="guid">The guid of the application using the device authentication definition class.</param>
    /// <returns>If successful, an instance of the device authentication definition class is returned.</returns>
    public static DeviceAuthenticationDefine LoadFromStream(Stream stream, string guid)
    {
        DeviceAuthenticationDefine result = null;
        using (MemoryStream inStream = new MemoryStream())
        {
            stream.CopyTo(inStream);
            inStream.Seek(0, SeekOrigin.Begin);
            using (MemoryStream outStream = new MemoryStream())
            {
                byte[] buffer = new byte[SIZE_BUFFER];

                _AES.GenerateIV();
                byte[] initVector = new byte[_AES.IV.Length];
                inStream.Read(initVector, 0, initVector.Length);
                _AES.IV = initVector;

                string key = guid.Replace("-", string.Empty);
                _AES.Key = Encoding.UTF8.GetBytes(key);

                int count;
                while((count = inStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    outStream.Write(buffer, 0, count);
                }

                byte[] buffer2 = outStream.ToArray();
                using (ICryptoTransform ct = _AES.CreateDecryptor())
                {
                    buffer2 = ct.TransformFinalBlock(buffer2, 0, buffer2.Length);
                }

                using (MemoryStream deserializeStream = new MemoryStream(buffer2))
                {
                    BinaryFormatter bf = new BinaryFormatter();
                    result = (DeviceAuthenticationDefine)bf.Deserialize(deserializeStream);
                }
            }
        }

        return result;
    }

    /// <summary>
    /// Writes the data of the device authentication definition class as a file.
    /// </summary>
    /// <param name="filePath">Path of the file to be written.</param>
    /// <param name="guid">The guid of the application using the device authentication definition file.</param>
    /// <param name="define">Instance of the device authentication definition class to be written.</param>
    public static void SaveFromFile(string filePath, string guid, DeviceAuthenticationDefine define)
    {
        using (MemoryStream ms = new MemoryStream())
        {
            BinaryFormatter bf = new BinaryFormatter();
            bf.Serialize(ms, define);

            byte[] buffer = ms.ToArray();
            _AES.GenerateIV();

            string key = guid.Replace("-", string.Empty);
            _AES.Key = Encoding.UTF8.GetBytes(key);
            using (ICryptoTransform ct = _AES.CreateEncryptor())
            {
                buffer = ct.TransformFinalBlock(buffer, 0, buffer.Length);
            }

            using(FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
            {
                fs.Write(_AES.IV, 0, _AES.IV.Length);
                fs.Write(buffer, 0, buffer.Length);
            }
        }
    }

    static DeviceAuthenticationDefineManagement()
    {
        _AES = new AesCryptoServiceProvider()
        {
            KeySize = SIZE_KEY,
            BlockSize = SIZE_BLOCK,
            Mode = CipherMode.CBC,
            Padding = PaddingMode.PKCS7
        };
    }
}