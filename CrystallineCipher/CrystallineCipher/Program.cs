using System;
using System.IO;
using CrystallineCipherLib;

namespace CrystallineCipher
{
    class Program
    {
        static void Main(string[] args)
        {
            int rounds = 8;

            //Crystalline 2
            Console.WriteLine("Crystalline 2");
            Console.WriteLine("Encrypting plain text...");
            File.WriteAllBytes(@"..\..\TestFiles\ciphertext.txt", Crystalline2.Encrypt(File.ReadAllBytes(@"..\..\TestFiles\plaintext.txt"), File.ReadAllBytes(@"..\..\TestFiles\k.rng"), File.ReadAllBytes(@"..\..\TestFiles\s.rng"), File.ReadAllBytes(@"..\..\TestFiles\s2.rng"), rounds));

            Console.WriteLine("Decrypting plain text...");
            File.WriteAllBytes(@"..\..\TestFiles\decipheredplaintext.txt", Crystalline2.Decrypt(File.ReadAllBytes(@"..\..\TestFiles\ciphertext.txt"), File.ReadAllBytes(@"..\..\TestFiles\k.rng"), File.ReadAllBytes(@"..\..\TestFiles\s.rng"), File.ReadAllBytes(@"..\..\TestFiles\s2.rng"), rounds));

            /*
             * Crystalline
            Console.WriteLine("Crystalline");
            Console.WriteLine("Encrypting plain text...");
            File.WriteAllBytes(@"..\..\TestFiles\ciphertext.txt", Crystalline2.Encrypt(File.ReadAllBytes(@"..\..\TestFiles\plaintext.txt"), File.ReadAllBytes(@"..\..\TestFiles\k.rng"), File.ReadAllBytes(@"..\..\TestFiles\s.rng"), rounds));

            Console.WriteLine("Decrypting plain text...");
            File.WriteAllBytes(@"..\..\TestFiles\decipheredplaintext.txt", Crystalline2.Decrypt(File.ReadAllBytes(@"..\..\TestFiles\ciphertext.txt"), File.ReadAllBytes(@"..\..\TestFiles\k.rng"), File.ReadAllBytes(@"..\..\TestFiles\s.rng"), rounds));

            */
            Console.WriteLine("Complete.  Press any key to continue...");
            Console.ReadKey();
        }
    }
}
