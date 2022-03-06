using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace BFW_Datensicherheit
{
    class CryptoSignature
    {
        static RSAParameters rsaKeyInfo;
        static byte[] hashValue;
        static byte[] signedHashValue;

        public static void Sign()
        {
            //Erstellen eines (zufälligen) Werts
            //(Wir verwenden hier Hashwerte, diese werden wir später genauer behandeln)
            HMACSHA256 sha = new HMACSHA256();
            hashValue = sha.ComputeHash(AsymmCrypto.ToByteArray<string>("Irgendwas"));


            //Wir erstellen einen neues RSA-Schlüsselpaar
            RSA rsa = RSA.Create();

            //Wir kreieren eine RSAPKCS1SignatureFormatter, welchem wir das RSA-Objekt übergeben. Dieser wird für das Signieren mit dem RSA verwendet.
            RSAPKCS1SignatureFormatter rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);

            //Wir setzen dann den Algorithmus 
            rsaFormatter.SetHashAlgorithm("SHA256");

            //Zum Schluss lassen wir das Objekt signieren
            signedHashValue = rsaFormatter.CreateSignature(hashValue);

            rsaKeyInfo = rsa.ExportParameters(false);

        }

        public static void Verify()
        {
            //Wir erstellen ein neues RSA-Objekt.
            RSA rsa = RSA.Create();

            //Wir importieren die Schlüsselinformationen. Hier reicht der PublicKey aus.
            rsa.ImportParameters(rsaKeyInfo);

            //Dann brauchen wir einen RSAPKCS1SignatureDeformatter, der uns die Signatur mit dem PublicKey wieder herstellt.
            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);

            //Dann setzen wir wieder den Hash-Algorithmus
            rsaDeformatter.SetHashAlgorithm("SHA256");

            //Zum Schluss können wir den Key verifizieren
            if (rsaDeformatter.VerifySignature(hashValue, signedHashValue))
            {
                Console.WriteLine("The signature is valid.");
            }
            else
            {
                Console.WriteLine("The signature is not valid.");
            }
        }
    }
}
