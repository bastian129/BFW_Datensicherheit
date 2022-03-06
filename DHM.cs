using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace BFW_Datensicherheit
{
    class DHM
    {
        //WICHTIG!!!
        //Wir verwenden hier CNG. CNG steht für

        public static void Start()
        {
            //Ich defininiere hier der Einfachheit beide Kommunikationspartner. In der Praxis liegen diese natürlich auf anderen Systemen.
            //Wir erzeugen zuerst jeweils ein Diffie-Hellman-Objekt.
            ECDiffieHellmanCng PartnerA = new ECDiffieHellmanCng();
            ECDiffieHellmanCng PartnerB = new ECDiffieHellmanCng();

            //Wir definieren nun die Art des Austauschs
            PartnerA.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            PartnerA.HashAlgorithm = CngAlgorithm.Sha256;

            PartnerB.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            PartnerB.HashAlgorithm = CngAlgorithm.Sha256;

            //Hier importieren wir den öffentlichen Schlüssel des anderen Partners
            byte[] KeyA = PartnerA.DeriveKeyMaterial(PartnerB.PublicKey);
            byte[] KeyB = PartnerB.DeriveKeyMaterial(PartnerA.PublicKey);

            Console.WriteLine("Partner A:");
            foreach (var element in KeyA)
                Console.Write(element + " ");
            Console.WriteLine();
            Console.WriteLine("Partner B:");
            foreach (var element in KeyB)
                Console.Write(element + " ");


        }
    }
}
