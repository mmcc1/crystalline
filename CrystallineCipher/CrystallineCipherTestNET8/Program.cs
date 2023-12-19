using CrystallineCipherLib;

namespace CrystallineCipherTestNET8
{
    internal class Program
    {
        static void Main(string[] args)
        {
            int rounds = 16;

            //Crystalline 3
            Console.WriteLine("Crystalline 4");
            Console.WriteLine("Encrypting...");
            File.WriteAllBytes(@"..\..\..\TestFiles\ciphertext4.txt", Crystalline4.Encrypt(File.ReadAllBytes(@"..\..\..\TestFiles\plaintext.txt"), File.ReadAllBytes(@"..\..\..\TestFiles\k.rng"), File.ReadAllBytes(@"..\..\..\TestFiles\s.rng"), File.ReadAllBytes(@"..\..\..\TestFiles\s2.rng"), rounds));

            Console.WriteLine("Decrypting...");
            File.WriteAllBytes(@"..\..\..\TestFiles\decipheredplaintext4.txt", Crystalline4.Decrypt(File.ReadAllBytes(@"..\..\..\TestFiles\ciphertext4.txt"), File.ReadAllBytes(@"..\..\..\TestFiles\k.rng"), File.ReadAllBytes(@"..\..\..\TestFiles\s.rng"), File.ReadAllBytes(@"..\..\..\TestFiles\s2.rng"), rounds));
        }
    }
}
