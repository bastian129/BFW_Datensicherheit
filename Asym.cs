using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;

namespace BFW_Datensicherheit
{
    class Asym
    {
        public static byte[] Encrypt(string val)
        {
            RSA rsa = RSA.Create();

            RSAParameters rSAParameters = rsa.ExportParameters(true);

            //Speichern des Schlüssels
            List<byte[]> keyList = new List<byte[]>() { rSAParameters.Modulus, rSAParameters.Exponent, rSAParameters.P, rSAParameters.Q, rSAParameters.DP, rSAParameters.DQ, rSAParameters.InverseQ, rSAParameters.D };
            File.WriteAllBytes("asymKey.dat", ToByteArray<List<byte[]>>(keyList));

            var encryptedData = rsa.Encrypt(ToByteArray<string>(val), RSAEncryptionPadding.OaepSHA256);

            foreach(var element in encryptedData) { Console.Write(element); }
            Console.WriteLine();
            return encryptedData;

        }

        public static string Decrypt(byte[] val)
        {
            RSA rsa = RSA.Create();

            RSAParameters rsaParameters = rsa.ExportParameters(true);

            var lis = FromByteArray<List<byte[]>>(File.ReadAllBytes("asymKey.dat"));

            rsaParameters.Modulus = lis[0];
            rsaParameters.Exponent = lis[1];
            rsaParameters.P = lis[2];
            rsaParameters.Q = lis[3];
            rsaParameters.DP = lis[4];
            rsaParameters.DQ = lis[5];
            rsaParameters.InverseQ = lis[6];
            rsaParameters.D = lis[7];

            rsa.ImportParameters(rsaParameters);

            string res = FromByteArray<string>( rsa.Decrypt(val, RSAEncryptionPadding.OaepSHA256));

            Console.WriteLine("Entschlüsselt: " + res);

            return res;

        }


        #region Hilfsmethoden
        //Hierbei handelt es sich um Methoden, mit Hilfe deren man aus Objekten byte-Arrays machen kann.
        public static byte[] ToByteArray<T>(T obj)
        {
            if (obj == null)
                return null;
            BinaryFormatter bf = new BinaryFormatter();
            using (MemoryStream ms = new MemoryStream())
            {
                bf.Serialize(ms, obj);
                return ms.ToArray();
            }
        }
        public static T FromByteArray<T>(byte[] data)
        {
            if (data == null)
                return default(T);
            BinaryFormatter bf = new BinaryFormatter();
            using (MemoryStream ms = new MemoryStream(data))
            {
                object obj = bf.Deserialize(ms);
                return (T)obj;
            }
        }

        #endregion
    }
}
