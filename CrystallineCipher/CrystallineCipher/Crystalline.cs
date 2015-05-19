using System;
using System.Collections;

namespace CrystallineCipher
{
    #region Technical Notes
    /* 
     * Recommend practice is to compress all files prior to encrypting
     * 
     */
    #endregion

    /// <summary>
    /// Crystalline Symmetric Cipher - Beta 3
    /// 
    /// Crystalline encrypts by manipulating the order of bits and bytes.  
    /// 
    /// The cipher is designed to resist cryptanalysis through information loss, 
    /// rather than hard to solve mathematical problems.  As such, attacks on the
    /// cipher will be in the form of side-channel attacks.  Information loss
    /// places this cipher in the same category as a one-time pad.
    /// 
    /// Copyright - Mark McCarron 2015
    /// License: MIT License
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
        public static byte[] Encrypt(byte[] inputData, byte[] key, byte[] salt, int iv)
        {
            int a = SelectValue(ref key, iv);
            int b = SelectValue(ref salt, a);
            int c = SelectValue(ref key, b);
            int d = SelectValue(ref salt, c);
            return CrystallineEncrypt(inputData, key, salt, ComputeRounds(a, b, c, d));
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherData">The data to decrypt</param>
        /// <param name="key">The passphrase</param>
        /// <param name="salt">The salt</param>
        /// <returns>Decrypted Data</returns>
        public static byte[] Decrypt(byte[] cipherData, byte[] key, byte[] salt, int iv)
        {
            int a = SelectValue(ref key, iv);
            int b = SelectValue(ref salt, a);
            int c = SelectValue(ref key, b);
            int d = SelectValue(ref salt, c);
            return CrystallineDecrypt(cipherData, key, salt, ComputeRounds(a, b, c, d));
        }

        #endregion

        #region Compute Rounds

        /// <summary>
        /// Compute Rounds: 10-27
        /// </summary>
        /// <returns>Number of Rounds</returns>
        private static int ComputeRounds(int keyByteValue1, int keyByteValue2, int keyByteValue3, int keyByteValue4)
        {
            int a = 0;
            try
            {
                a = ((keyByteValue1 / 10) + (keyByteValue2 / 10) + (keyByteValue3 / 10) + (keyByteValue4 / 10)) / 4;
            }
            catch 
            {
                return 27;
            } 

            if (a < 10)
                return 10 + a;
            else
                return a;
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
                    data[currentLocation] = data[currentLocation] ^ true;

                bool temp = data[newLocation];
                data[newLocation] = data[currentLocation];
                data[currentLocation] = temp;

                if (isDecrypt)
                    data[currentLocation] = data[currentLocation] ^ true;
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
                    data[currentLocation] = data[currentLocation] ^ true;

                bool temp = data[newLocation];
                data[newLocation] = data[currentLocation];
                data[currentLocation] = temp;

                if (isDecrypt)
                    data[currentLocation] = data[currentLocation] ^ true;
            }
        }
        #endregion

        #region Helper Functions

        #region Select a value from an array

        /// <summary>
        /// Select a value from an array
        /// </summary>
        /// <param name="data">Array</param>
        /// <param name="keyByteValue">Value</param>
        /// <returns>value from array</returns>
        private static int SelectValue(ref byte[] data, int keyByteValue)
        {
            return data[keyByteValue % data.Length];
        }

        #endregion

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

        #endregion
    }
}
