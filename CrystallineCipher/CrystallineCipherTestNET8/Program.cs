using CrystallineCipherLib;

namespace CrystallineCipherTestNET8
{
    internal class Program
    {
        static void Main(string[] args)
        {
            int rounds = 16;

            //Crystalline 3
            Console.WriteLine("Crystalline 3");
            Console.WriteLine("Encrypting plain text...");
            File.WriteAllBytes(@"..\..\..\TestFiles\ciphertext3.txt", Crystalline3.Encrypt(File.ReadAllBytes(@"..\..\..\TestFiles\plaintext.txt"), File.ReadAllBytes(@"..\..\..\TestFiles\k.rng"), File.ReadAllBytes(@"..\..\..\TestFiles\s.rng"), File.ReadAllBytes(@"..\..\..\TestFiles\s2.rng"), rounds));

            Console.WriteLine("Decrypting plain text...");
            File.WriteAllBytes(@"..\..\..\TestFiles\decipheredplaintext3.txt", Crystalline3.Decrypt(File.ReadAllBytes(@"..\..\..\TestFiles\ciphertext3.txt"), File.ReadAllBytes(@"..\..\..\TestFiles\k.rng"), File.ReadAllBytes(@"..\..\..\TestFiles\s.rng"), File.ReadAllBytes(@"..\..\..\TestFiles\s2.rng"), rounds));
        }
    }
}
