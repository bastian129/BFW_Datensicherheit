using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;

namespace BFW_Datensicherheit
{
    //Disclaimer: Achten Sie bitte darauf, dass es sich hier nicht um eine Musterlösung für eine gut implementierte Verschlüsselung handelt! Dieser Code dient nur zur Darstellung der RSA-Verschlüsselung!
    class AsymmCrypto
    {
        public static byte[] Encrypt(string val)
        {
            //Wir erstellen zuerst wieder eine neue Instanz des RSA-Algorithmus. Dabei werden wieder automatisch ein privater und ein öffentlicher Schlüssel erzeugt.
            RSA rsa = RSA.Create();

            //Diese beiden werden raltiv mathematisch als Modulus und Exponent gespeichert. Um an die Werte heran zu kommen, müssen wir zuerst die Parameter exportieren. Dabei sagt der Boolean in den Klammern, ob der private Schlüssel auch exportiert werden soll.
            RSAParameters rsaParameter = rsa.ExportParameters(true);

            //Sie haben nun die Möglichkeit, schon vorhandene Daten einzulesen.
            if (File.Exists("asymKey.dat"))
            {
                var lis = FromByteArray<List<byte[]>>(File.ReadAllBytes("asymKey.dat"));

                //Modulus und Exponent ergeben dabei den PublicKey
                rsaParameter.Modulus = lis[0];
                rsaParameter.Exponent = lis[1];

                rsaParameter.P = lis[2];
                rsaParameter.Q = lis[3];
                rsaParameter.DP = lis[4];
                rsaParameter.DQ = lis[5];
                rsaParameter.InverseQ = lis[6];
                rsaParameter.D = lis[7];
                rsa.ImportParameters(rsaParameter);
            }

            //Jetzt können wir auf alle Werte zugreifen und sie ggf. abspeichern.
            List<byte[]> keyList = new List<byte[]>() { rsaParameter.Modulus, rsaParameter.Exponent, rsaParameter.P, rsaParameter.Q, rsaParameter.DP, rsaParameter.DQ, rsaParameter.InverseQ, rsaParameter.D };
            File.WriteAllBytes("asymKey.dat", ToByteArray<List<byte[]>>(keyList));

            //Jetzt kann verschlüsselt werden. Ich gebe hier die verschlüsselten Daten auch gleich aus.
            var encryptedData = rsa.Encrypt(ToByteArray<string>(val), RSAEncryptionPadding.OaepSHA256);
            Console.Write("Verschlüsselte Daten: ");
            foreach (var element in encryptedData) { Console.Write(element + " "); }
            Console.WriteLine();

            return encryptedData;
        }

        public static string Decrypt(byte[] val)
        {
            //Wir erstellen zuerst wieder eine neue Instanz des RSA-Algorithmus. Dabei werden wieder automatisch ein privater und ein öffentlicher Schlüssel erzeugt.
            RSA rsa = RSA.Create();

            //Diese beiden werden raltiv mathematisch als Modulus und Exponent gespeichert. Um an die Werte heran zu kommen, müssen wir zuerst die Parameter exportieren. Dabei sagt der Boolean in den Klammern, ob der private Schlüssel auch exportiert werden soll.
            RSAParameters rsaParameter = rsa.ExportParameters(true);

            //Sie haben nun die Möglichkeit, schon vorhandene Daten einzulesen.
            if (File.Exists("asymKey.dat"))
            {
                var lis = FromByteArray<List<byte[]>>(File.ReadAllBytes("asymKey.dat"));

                //Modulus und Exponent ergeben dabei den PublicKey
                rsaParameter.Modulus = lis[0];
                rsaParameter.Exponent = lis[1];

                rsaParameter.P = lis[2];
                rsaParameter.Q = lis[3];
                rsaParameter.DP = lis[4];
                rsaParameter.DQ = lis[5];
                rsaParameter.InverseQ = lis[6];
                rsaParameter.D = lis[7];
                rsa.ImportParameters(rsaParameter);
            }

            //Dann können die Daten natürlich auch wieder entschlüsselt werden.
            string decryptedData = FromByteArray<string>(rsa.Decrypt(val, RSAEncryptionPadding.OaepSHA256));
            Console.WriteLine("Entschlüsselte Daten: " + decryptedData);

            return decryptedData;
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
