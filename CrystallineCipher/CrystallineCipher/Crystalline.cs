using System;
using System.Collections;

namespace CrystallineCipher
{
    #region Technical Notes
    /* 
     * Key strength: 
     * Arbitrary
     * 
     * Lowest recommended standard for Key and salt:
     * 16Kb - 131072 bits
     * 
     * Recommended practice around keys and salt:
     * Random length > 16KB
     * 
     * Source for truely random (atmospheric noise) bytes for passphrase and salt:
     * https://www.random.org/bytes/
     * 
     * Permuations in output ciphertext:
     * ((256*256)^(bits in plaintext) + (256*256)^(bytes in plaintext)) * rounds
     * 
     * Known Weaknesses:
     * None.
     * 
     * Example Randomness Tests (similar to random source derived from radioactive 
     * decay):
     * 
     * ENT
     * http://www.fourmilab.ch/random/
     * 
     * 
     * Entropy = 7.999571 bits per byte.
     * 
     * Optimum compression would reduce the size
     * of this 432138 byte file by 0 percent.
     * 
     * Chi square distribution for 432138 samples is 256.72, and randomly
     * would exceed this value 45.80 percent of the times.
     * 
     * Arithmetic mean value of data bytes is 127.6506 (127.5 = random).
     * Monte Carlo value for Pi is 3.139497105 (error 0.07 percent).
     * Serial correlation coefficient is 0.001534 (totally uncorrelated = 0.0).
     * 
     * 
     * Entropy = 7.999922 bits per byte.
     * Optimum compression would reduce the size
     * of this 2345986 byte file by 0 percent.
     * 
     * Chi square distribution for 2345986 samples is 252.18, and randomly
     * would exceed this value 53.81 percent of the times.
     * 
     * Arithmetic mean value of data bytes is 127.5545 (127.5 = random).
     * Monte Carlo value for Pi is 3.137896199 (error 0.12 percent).
     * Serial correlation coefficient is 0.000181 (totally uncorrelated = 0.0).
     * 
     * 
     * Entropy = 7.999925 bits per byte.
     * Optimum compression would reduce the size 
     * of this 2345986 byte file by 0 percent.
     * 
     * Chi square distribution for 2345986 samples is 245.20, and randomly
     * would exceed this value 65.91 percent of the times.
     * 
     * Arithmetic mean value of data bytes is 127.4954 (127.5 = random).
     * Monte Carlo value for Pi is 3.139205672 (error 0.08 percent).
     * Serial correlation coefficient is -0.001167 (totally uncorrelated = 0.0).
     */
    #endregion

    /// <summary>
    /// Crystalline Symmetric Cipher
    /// 
    /// Copyright - Mark McCarron 2015 - All rights reserved.
    /// 
    /// Crystalline encrypts by manipulating the order of bits and bytes.  
    /// 
    /// The cipher is designed to resist cryptanalysis through information loss, 
    /// rather than hard to solve mathematical problems.  As such, attacks on the
    /// cipher will be in the form of side-channel attacks.  Information loss
    /// places this cipher in the same category as a one-time pad.
    /// </summary>
    public static class Crystalline
    {
        #region Encrypt/Decrypt public methods

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="inputData">The data to encrypt</param>
        /// <param name="key">The passphrase</param>
        /// <param name="salt">The salt</param>
        /// <returns>Encrypted Data</returns>
        public static byte[] Encrypt(byte[] inputData, byte[] key, byte[] salt)
        {
            return CrystallineEncrypt(inputData, key, salt, CrysallineDepth());
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherData">The data to decrypt</param>
        /// <param name="key">The passphrase</param>
        /// <param name="salt">The salt</param>
        /// <returns>Decrypted Data</returns>
        public static byte[] Decrypt(byte[] cipherData, byte[] key, byte[] salt)
        {
            return CrystallineDecrypt(cipherData, key, salt, CrysallineDepth());
        }

        #endregion

        #region Crystalline Depth

        /// <summary>
        /// Compute Rounds - Can be varied for specific files/key/salt - But test for randomness
        /// </summary>
        /// <returns>Number of Rounds</returns>
        private static int CrysallineDepth()
        {
            return 8;
        }

        #endregion

        #region Encryption and Decryption

        /// <summary>
        /// Main Encryption Method
        /// </summary>
        /// <param name="inputData">The data to encrypt</param>
        /// <param name="key">The passphrase</param>
        /// <param name="salt">The salt</param>
        /// <param name="rounds">Number of Rounds</param>
        /// <returns>Encrypted Data</returns>
        private static byte[] CrystallineEncrypt(byte[] inputData, byte[] key, byte[] salt, int rounds)
        {
            while (rounds >= 0)
            {
                #region By Bit

                BitArray bitArray = new BitArray(inputData);

                bool isUp = false;
                int keyIndex = 0;
                int saltIndex = 0;

                for (int i = 0; i < bitArray.Length; i++)
                {
                    int offset = Shift(key[keyIndex++], salt[saltIndex++]);

                    PerformBitShiftMod(ref bitArray, i, offset, isUp, false);

                    isUp = isUp == false ? true : false;

                    if (keyIndex == key.Length)
                        keyIndex = 0;

                    if (saltIndex == salt.Length)
                        saltIndex = 0;
                }

                byte[] cipherData = BitArrayToByteArray(bitArray);

                #endregion

                #region By Byte

                isUp = false;
                keyIndex = 0;
                saltIndex = 0;

                for (int i = 0; i < cipherData.Length; i++)
                {
                    int offset = Shift(key[keyIndex++], salt[saltIndex++]);

                    PerformByteShiftMod(ref cipherData, i, offset, isUp);

                    isUp = isUp == false ? true : false;

                    if (keyIndex == key.Length)
                        keyIndex = 0;

                    if (saltIndex == salt.Length)
                        saltIndex = 0;
                }

                #endregion

                rounds--;

                if (rounds == -1)
                    return cipherData;
                else
                    inputData = cipherData;
            }

            return null;
        }

        /// <summary>
        /// Main Decryption Method
        /// </summary>
        /// <param name="cipherData">The data to encrypt</param>
        /// <param name="key">>The passphrase</param>
        /// <param name="salt">The salt</param>
        /// <param name="rounds">Number of Rounds</param>
        /// <returns>Decrypted Data</returns>
        private static byte[] CrystallineDecrypt(byte[] cipherData, byte[] key, byte[] salt, int rounds)
        {
            while (rounds >= 0)
            {
                #region By Byte

                bool isUp = false;
                int keyIndex = 0;
                int saltIndex = 0;

                InitDecodeValues(cipherData.Length, key.Length, ref keyIndex, salt.Length, ref saltIndex, ref isUp);

                for (int i = cipherData.Length - 1; i >= 0; i--)
                {
                    int offset = Shift(key[keyIndex--], salt[saltIndex--]);

                    PerformByteShiftMod(ref cipherData, i, offset, isUp);

                    isUp = isUp == false ? true : false;

                    if (keyIndex == -1)
                        keyIndex = key.Length - 1;

                    if (saltIndex == -1)
                        saltIndex = salt.Length - 1;
                }

                #endregion

                #region By Bit

                BitArray plainData = new BitArray(cipherData);

                keyIndex = 0;
                saltIndex = 0;

                int a = plainData.Count;
                int b = plainData.Length;
                InitDecodeValues(plainData.Count, key.Length, ref keyIndex, salt.Length, ref saltIndex, ref isUp);

                for (int i = plainData.Count - 1; i >= 0; i--)
                {
                    int offset = Shift(key[keyIndex--], salt[saltIndex--]);

                    PerformBitShiftMod(ref plainData, i, offset, isUp, true);

                    isUp = isUp == false ? true : false;

                    if (keyIndex == -1)
                        keyIndex = key.Length - 1;

                    if (saltIndex == -1)
                        saltIndex = salt.Length - 1;
                }

                #endregion

                rounds--;

                if (rounds == -1)
                    return BitArrayToByteArray(plainData);
                else
                    cipherData = BitArrayToByteArray(plainData);
            }

            return null;
        }

        #endregion

        #region Shift Offset

        /// <summary>
        /// Calculate the new location of bit/byte
        /// </summary>
        /// <param name="key">The passphrase</param>
        /// <param name="salt">The salt</param>
        /// <returns>New location</returns>
        private static int Shift(byte key, byte salt)
        {
            return (int)key * (int)salt;
        }

        #endregion

        #region Perform Byte Shift

        /// <summary>
        /// Moves byte to a new location
        /// </summary>
        /// <param name="data">The encrypted/decrypted data</param>
        /// <param name="currentLocation">The current location of a byte</param>
        /// <param name="offSet">The new position of byte</param>
        /// <param name="isUp">The direction of movement</param>
        public static void PerformByteShiftMod(ref byte[] data, int currentLocation, int offSet, bool isUp)
        {
            if (isUp)
            {
                int newLocation = (currentLocation + offSet) % data.Length;

                byte temp = data[newLocation];
                data[newLocation] = data[currentLocation];
                data[currentLocation] = temp;
            }
            else
            {
                int newLocation = (currentLocation - offSet);

                if (newLocation < 0)
                {
                    newLocation = -newLocation;
                    newLocation = (data.Length) - (newLocation % data.Length);
                }

                if (newLocation > data.Length - 1)
                {
                    newLocation = -newLocation;
                    newLocation = (newLocation % data.Length);
                }

                byte temp = data[newLocation];
                data[newLocation] = data[currentLocation];
                data[currentLocation] = temp;
            }
        }

        #endregion

        #region Perform Bit Shift

        /// <summary>
        /// Moves bit to a new location
        /// </summary>
        /// <param name="bitArray">The encrypted/decrypted data as a array of bits</param>
        /// <param name="currentLocation">The current location of a bit</param>
        /// <param name="offSet">The new position of bit</param>
        /// <param name="isUp">The direction of movement</param>
        public static void PerformBitShiftMod(ref BitArray data, int currentLocation, int offSet, bool isUp, bool isDecrypt)
        {
            if (isUp)
            {
                int newLocation = (currentLocation + offSet) % data.Length;

                if (!isDecrypt)
                    data[currentLocation] = XOR(data[currentLocation], true);

                bool temp = data[newLocation];
                data[newLocation] = data[currentLocation];
                data[currentLocation] = temp;

                if (isDecrypt)
                    data[currentLocation] = XOR(data[currentLocation], true);
            }
            else
            {
                int newLocation = (currentLocation - offSet);

                if (newLocation < 0)
                {
                    newLocation = -newLocation;
                    newLocation = (data.Length) - (newLocation % data.Length);
                }

                if (newLocation > data.Length - 1)
                {
                    newLocation = -newLocation;
                    newLocation = (newLocation % data.Length);
                }

                if (!isDecrypt)
                    data[currentLocation] = XOR(data[currentLocation], true);

                bool temp = data[newLocation];
                data[newLocation] = data[currentLocation];
                data[currentLocation] = temp;

                if (isDecrypt)
                    data[currentLocation] = XOR(data[currentLocation], true);
            }
        }
        #endregion

        #region Helper Functions

        #region Initialise Decode Values

        /// <summary>
        /// Set starting values in decode
        /// </summary>
        /// <param name="dataLength">The length of the data to decrypt</param>
        /// <param name="keyLength">The passphrase length</param>
        /// <param name="keyIndex">Counter for passphrase</param>
        /// <param name="saltLength">The salt length</param>
        /// <param name="saltIndex">Counter for the salt</param>
        /// <param name="isUp">Direction of movement</param>
        private static void InitDecodeValues(int dataLength, int keyLength, ref int keyIndex, int saltLength, ref int saltIndex, ref bool isUp)
        {
            isUp = dataLength % 2 != 0 ? false : true;

            for (int i = 0; i < dataLength - 1; i++)
            {
                keyIndex++;

                if (keyIndex == keyLength)
                    keyIndex = 0;
            }

            for (int i = 0; i < dataLength - 1; i++)
            {
                saltIndex++;

                if (saltIndex == saltLength)
                    saltIndex = 0;
            }
        }

        #endregion

        #region BitArray To ByteArray

        #region Licence for BitArrayToByteArray Method
        // Copyright (c) 2007 James Newton-King
        //
        // Permission is hereby granted, free of charge, to any person
        // obtaining a copy of this software and associated documentation
        // files (the "Software"), to deal in the Software without
        // restriction, including without limitation the rights to use,
        // copy, modify, merge, publish, distribute, sublicense, and/or sell
        // copies of the Software, and to permit persons to whom the
        // Software is furnished to do so, subject to the following
        // conditions:
        //
        // The above copyright notice and this permission notice shall be
        // included in all copies or substantial portions of the Software.
        //
        // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        // EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
        // OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        // NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
        // HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
        // WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
        // FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
        // OTHER DEALINGS IN THE SOFTWARE.
        #endregion

        /// <summary>
        /// Convert Bit Array To Byte with Endiness suitable for Intel
        /// </summary>
        /// <param name="bits">The BitArray</param>
        /// <returns>Data array</returns>
        public static byte[] BitArrayToByteArray(this BitArray bits)
        {
            return BitArrayToByteArray(bits, 0, bits.Length, 8);
        }

        public static byte[] BitArrayToByteArray(this BitArray bits, int startIndex, int count, int ByteLength)
        {
            int bytesize = count / ByteLength;

            if (count % ByteLength > 0)
                bytesize++;

            byte[] bytes = new byte[bytesize];

            byte value = 0;
            byte significance = 1;

            int bytepos = 0;
            int bitpos = startIndex;

            while (bitpos - startIndex < count)
            {
                if (bits[bitpos])
                    value += significance;

                bitpos++;

                if (bitpos % ByteLength == 0)
                {
                    bytes[bytepos] = value;
                    bytepos++;
                    value = 0;
                    significance = 1;
                }
                else
                {
                    significance *= 2;
                }
            }
            return bytes;
        }

        #endregion

        public static bool XOR(bool value1, bool value2)
        {
            if (value1 != value2)
                return true;
            else
                return false;
        }

        #endregion
    }
}
