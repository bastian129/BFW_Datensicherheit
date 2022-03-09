using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace BFW_Datensicherheit
{
    class Signature
    {
        static RSAParameters publicKey;
        static byte[] hashValue;
        static byte[] signedHashValue;

        public static void Sign()
        {
            HMACSHA256 sha = new HMACSHA256();
            hashValue = sha.ComputeHash(AsymmCrypto.ToByteArray<string>("Irgendwas"));

            RSA rsa = RSA.Create();

            RSAPKCS1SignatureFormatter rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);

            rsaFormatter.SetHashAlgorithm("SHA256");

            signedHashValue = rsaFormatter.CreateSignature(hashValue);

            RSA rsa2 = RSA.Create();
            publicKey = rsa2.ExportParameters(false);
        }

        public static void Verify()
        {
            RSA rsa = RSA.Create(publicKey);

            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaDeformatter.SetHashAlgorithm("SHA256");

            bool b = rsaDeformatter.VerifySignature(hashValue, signedHashValue);

            if (b == true)
                Console.WriteLine("RICHTIG!");
            else
                Console.WriteLine("FALSCH!");
        }
    }
}
