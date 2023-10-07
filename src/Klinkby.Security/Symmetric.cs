using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;

namespace Klinkby.Security;

public class SymmetricEncryption
{
    private static readonly Encoding Encoding = Encoding.UTF8;
    private readonly byte[] _keyBytes;

    public SymmetricEncryption(string secretKey)
    {
        // generate a 256 bit key from https://www.grc.com/passwords.htm
        _keyBytes = Enumerable.Range(0, secretKey.Length / 2)
            .Select(i => byte.Parse(
                secretKey.Substring(i * 2, 2),
                NumberStyles.HexNumber))
            .ToArray();
    }


    public string Decrypt(string encryptedText)
    {
        var plainBytes = DecryptBytes(encryptedText);
        return Encoding.GetString(plainBytes).TrimEnd('\0');
    }

    public byte[] DecryptBytes(string encryptedText)
    {
        if (string.IsNullOrEmpty(encryptedText))
            return new byte[0];
        var encryptedBytes = FromBase64Url(encryptedText);
        byte[] plainBytes;
        using (var aes = CreateCryptoService())
        {
            using (var dec = aes.CreateDecryptor())
            {
                plainBytes = dec.TransformFinalBlock(
                    encryptedBytes,
                    0,
                    encryptedBytes.Length);
                plainBytes = plainBytes.Skip(aes.IV.Length).ToArray();
            }
        }

        return plainBytes;
    }

    public string SerializeEncrypt(object obj)
    {
        string encrypted;
        using (var ms = new MemoryStream())
        {
            var writer = new BsonDataWriter(ms);
            var ser = new JsonSerializer();
            ser.Serialize(writer, obj);
            writer.Flush();
            encrypted = EncryptBytes(ms.ToArray());
        }

        return encrypted;
    }

    public T? DecryptDeserialize<T>(string encrypted)
    {
        var plainBytes = DecryptBytes(encrypted);
        T? obj;
        using var ms = new MemoryStream(plainBytes);
        var reader = new BsonDataReader(ms);
        var ser = new JsonSerializer();
        obj = ser.Deserialize<T>(reader);

        return obj;
    }

    public string Encrypt(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
            return string.Empty;
        var plainBytes = Encoding.GetBytes(plainText);
        var encrypted = EncryptBytes(plainBytes);
        return encrypted;
    }

    public string EncryptBytes(byte[] plainBytes)
    {
        if (null == plainBytes || 0 == plainBytes.Length)
            return string.Empty;
        byte[] encryptedBytes;
        using var aes = CreateCryptoService();
        plainBytes = PadLeftRandomBytes(plainBytes, aes.IV.Length);
        using (var enc = aes.CreateEncryptor())
        {
            encryptedBytes = enc.TransformFinalBlock(
                plainBytes,
                0,
                plainBytes.Length);
        }

        return ToBase64Url(encryptedBytes);
    }

    private Aes CreateCryptoService()
    {
        var aes = Aes.Create();
        aes.GenerateIV();
        aes.Key = _keyBytes;
        aes.Padding = PaddingMode.Zeros;
        return aes;
    }

    private static byte[] TrimLeftBytes(byte[] arr, int length)
    {
        var buf = new byte[arr.Length - length];
        Array.Copy(arr, length, buf, 0, buf.Length);
        return buf;
    }

    private static byte[] PadLeftRandomBytes(byte[] arr, int length)
    {
        var buf = new byte[length];
        RndGen.Random.GetBytes(buf);
        Array.Resize(ref buf, length + arr.Length);
        Array.Copy(arr, 0, buf, length, arr.Length);
        return buf;
    }

    public static string ToBase64Url(byte[] buf)
    {
        var base64 = Convert.ToBase64String(buf);
        var url = base64
            .TrimEnd('=') // remove the base64 padding =
            .Replace('+', '-')
            .Replace('/', '_');
        return url;
    }

    public static byte[] FromBase64Url(string url)
    {
        var len = url.Length;
        var base64 = url.Replace('-', '+')
            .Replace('_', '/')
            .PadRight(
                len + (4 - len % 4) % 4,
                '='); // reapply the base64 padding =
        var buf = Convert.FromBase64String(base64);
        return buf;
    }
}