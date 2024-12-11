using CrystallineCipherLib;
using System.Security.Cryptography;

namespace CrystallineCipherTestNET8
{
    internal class Program
    {
        static void Main(string[] args)
        {
            //int rounds = 16;

            ////Crystalline 4
            //Console.WriteLine("Crystalline 4");
            //Console.WriteLine("Encrypting...");
            //File.WriteAllBytes(@"..\..\..\TestFiles\ciphertext4.txt", Crystalline4.Encrypt(File.ReadAllBytes(@"..\..\..\TestFiles\plaintext.txt"), File.ReadAllBytes(@"..\..\..\TestFiles\k.rng"), File.ReadAllBytes(@"..\..\..\TestFiles\s.rng"), File.ReadAllBytes(@"..\..\..\TestFiles\s2.rng"), rounds));

            //Console.WriteLine("Decrypting...");
            //File.WriteAllBytes(@"..\..\..\TestFiles\decipheredplaintext4.txt", Crystalline4.Decrypt(File.ReadAllBytes(@"..\..\..\TestFiles\ciphertext4.txt"), File.ReadAllBytes(@"..\..\..\TestFiles\k.rng"), File.ReadAllBytes(@"..\..\..\TestFiles\s.rng"), File.ReadAllBytes(@"..\..\..\TestFiles\s2.rng"), rounds));

            int keySaltSize = 65536;
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            List<byte[]> rngBytes = new List<byte[]>();

            for(int i = 0; i < 3; i++)
            {
                byte[] bytes = new byte[keySaltSize];
                rng.GetBytes(bytes);
                rngBytes.Add(bytes);
            }

            File.WriteAllBytes(@"..\..\..\TestFiles2\k.rng", rngBytes.ElementAt(0));
            File.WriteAllBytes(@"..\..\..\TestFiles2\s.rng", rngBytes.ElementAt(0));
            File.WriteAllBytes(@"..\..\..\TestFiles2\s2.rng", rngBytes.ElementAt(0));

            int rounds = 32;

            //Crystalline 5
            Console.WriteLine("Crystalline 5");
            Console.WriteLine("Encrypting...");
            File.WriteAllBytes(@"..\..\..\TestFiles2\ciphertext5.txt", Crystalline5.Encrypt(File.ReadAllBytes(@"..\..\..\TestFiles2\plaintext.txt"), File.ReadAllBytes(@"..\..\..\TestFiles2\k.rng"), File.ReadAllBytes(@"..\..\..\TestFiles2\s.rng"), File.ReadAllBytes(@"..\..\..\TestFiles2\s2.rng"), rounds));

            Console.WriteLine("Decrypting...");
            File.WriteAllBytes(@"..\..\..\TestFiles2\decipheredplaintext5.txt", Crystalline5.Decrypt(File.ReadAllBytes(@"..\..\..\TestFiles2\ciphertext5.txt"), File.ReadAllBytes(@"..\..\..\TestFiles2\k.rng"), File.ReadAllBytes(@"..\..\..\TestFiles2\s.rng"), File.ReadAllBytes(@"..\..\..\TestFiles2\s2.rng"), rounds));
        }
    }
}
