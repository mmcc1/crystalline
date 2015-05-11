using System;
using System.IO;

namespace CrystallineCipher
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Encrypting plain text...");
            File.WriteAllBytes(@"..\..\TestFiles\ciphertext.txt", Crystalline.Encrypt(File.ReadAllBytes(@"..\..\TestFiles\plaintext.txt"), File.ReadAllBytes(@"..\..\TestFiles\key.txt"), File.ReadAllBytes(@"..\..\TestFiles\salt.txt")));

            Console.WriteLine("Decrypting plain text...");
            File.WriteAllBytes(@"..\..\TestFiles\deciphered.txt", Crystalline.Decrypt(File.ReadAllBytes(@"..\..\TestFiles\ciphertext.txt"), File.ReadAllBytes(@"..\..\TestFiles\key.txt"), File.ReadAllBytes(@"..\..\TestFiles\salt.txt")));

            Console.WriteLine("Complete.  Press any key to continue...");
            Console.ReadKey();
        }
    }
}
