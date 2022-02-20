using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;

namespace BFW_Datensicherheit
{
    class SynchCrypto
    {
        public static void Encrypt(string message)
        {
            try
            {
                //Ein AES-Objekt erstellen
                Aes aes = Aes.Create();
                //Zu Beginn werden Key und IV automatisch kreiert. Will man diese neu erzeugen, ruft man einfach folgende zwei Methoden aus:
                aes.GenerateIV();
                aes.GenerateKey();
                //In dem Feld 'Key' befindet sich der generierte Schlüssel. Dieser wird in diesem Beispiel in eine Datei geschrieben.
                File.WriteAllBytes("key.dat", aes.Key);
                //Wichtig! Man muss auch die IV speichern, da man diese zum Entschlüsseln braucht.
                File.WriteAllBytes("iv.dat", aes.IV);

                //Hier werden jetzt Using-Advices verwendet, dass die Streams gleich nach dem Verwenden wieder geschlossen werden. Dadurch wird sichergestellt, dass die Resourcen wieder freigegeben werden.
                //Wir brauchen dann einen Speicherort für die verschlüsselte Datei
                using (FileStream fileStream = new FileStream("msg.crypto", FileMode.OpenOrCreate))
                {
                    //Hier erstellen wir den Stream, der für die Verschlüsselung zuständig ist.
                    using (CryptoStream cryptoStream = new CryptoStream(fileStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        //Zum Schluss brauchen wir noch den StreamWriter, der uns den Stream in der Speicher schreibt.
                        using (StreamWriter encryptWriter = new StreamWriter(cryptoStream))
                        {
                            encryptWriter.WriteLine(message);
                        }
                    }
                }
            }
            catch(Exception ex)
            {
                Console.WriteLine("Fehler aufgetreten: " + ex.ToString());
            }
        }


        public static string Decrypt()
        {
            try
            {
                //Ein AES-Objekt erstellen
                Aes aes = Aes.Create();

                //Natürlich kann man auch aus einer Datei einen Schlüssel laden. Dafür weißt man dem Feld 'Key' einfach den Wert zu:
                if (File.Exists("key.dat"))
                    aes.Key = File.ReadAllBytes("key.dat");
                //Natürlich kann man auch aus einer Datei eine IV laden. Dafür weißt man dem Feld 'IV' einfach den jeweiligen Wert zu:
                if (File.Exists("iv.dat"))
                    aes.IV = File.ReadAllBytes("iv.dat");

                //Hier werden jetzt Using-Advices verwendet, dass die Streams gleich nach dem Verwenden wieder geschlossen werden. Dadurch wird sichergestellt, dass die Resourcen wieder freigegeben werden.
                //Wir brauchen dann einen Speicherort für die verschlüsselte Datei
                using (FileStream fileStream = new FileStream("msg.crypto", FileMode.Open))
                {
                    //Hier erstellen wir den Stream, der für die Verschlüsselung zuständig ist.
                    using (CryptoStream cryptoStream = new CryptoStream(fileStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        //Zum Schluss brauchen wir noch den StreamWriter, der uns den Stream in der Speicher schreibt.
                        using (StreamReader decryptReader = new StreamReader(cryptoStream))
                        {
                            //Jetzt lesen wir einfach noch den Text aus. Im Zuge dessen wird dieser dann auch entschlüsselt:
                            string text = decryptReader.ReadToEnd();
                            return text;
                        }
                    }
                }
            }
            catch(Exception ex)
            {
                Console.WriteLine("Fehler aufgetreten: " + ex.ToString());
                return null;
            }
        }

    }
}
