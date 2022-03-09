using System;

namespace BFW_Datensicherheit
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            Signature.Sign();
            Signature.Verify();
        }
    }
}
