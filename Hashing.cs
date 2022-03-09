using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace BFW_Datensicherheit
{
    class Hashing
    {
        public static byte[] HashValue(string str)
        {
            //Zuerst erstellen wir ein Objekt der Klasse. In diesem Beispiel verwenden wir einen SHA256-Hash. Natürlich könnten Sie auch SHA512 oder MD5 verwenden.
            SHA256 sha = SHA256.Create();
            //Wir müssen dann den String, den wir hashen wollen, in ein byte-Array umwandeln. Sie können jede Art von Objekt hashen, nicht nur strings.
            var bytes = AsymmCrypto.ToByteArray<string>(str);
            //Zum Schluss führen wir den Hashvorgang aus. Mit ComputeHash() bekommen wir dann von dem übergebenen bytes den Hashwert zurück.
            var hashValue = sha.ComputeHash(bytes);

            return hashValue;
        }
    }
}
