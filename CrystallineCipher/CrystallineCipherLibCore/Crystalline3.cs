/* Crystalline 3 Symmetric Cipher
 * Copyright: Mark McCarron (Marx Bitware) - 2023
 * 
 * This source code is provided with multiple licenses. Select the license
 * most applicable to your intended application. Just add the relevent license
 * to this section of your code and fill in the blanks if required.
 * 
 * This code can be used in both commercial and open-source products.
 * 
 * Apache - http://www.apache.org/licenses/LICENSE-2.0
 * BSD 3-Clause - https://opensource.org/licenses/BSD-3-Clause
 * BSD 2-Clause - https://opensource.org/licenses/BSD-2-Clause
 * WTFPL - http://www.wtfpl.net/about/
 * MIT - https://opensource.org/licenses/MIT
 * LGPL v3.0 - http://www.gnu.org/licenses/lgpl-3.0.en.html
 * LGPL v2.1 - http://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html
 * GPL v3.0 - http://www.gnu.org/licenses/gpl-3.0.en.html
 * GPL v2.0 - http://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html
 */

using System.Collections;

namespace CrystallineCipherLib
{
    /// <summary>
    /// Crystalline 3 Symmetric Cipher
    /// Expanded Shift - 16777216
    /// Employs a byte shift, bit shift, then byte shift pattern
    /// </summary>
    public static class Crystalline3
    {
        #region Encrypt/Decrypt public methods

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="salt"></param>
        /// <param name="salt2"></param>
        /// <param name="rounds"></param>
        /// <returns></returns>
        public static byte[] Encrypt(byte[] data, byte[] key, byte[] salt, byte[] salt2, int rounds)
        {
            return CrystallineEncrypt(data, key, salt, salt2, rounds);
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="salt"></param>
        /// <param name="salt2"></param>
        /// <param name="rounds"></param>
        /// <returns></returns>
        public static byte[] Decrypt(byte[] data, byte[] key, byte[] salt, byte[] salt2, int rounds)
        {
            return CrystallineDecrypt(data, key, salt, salt2, rounds);
        }

        #endregion

        #region Encryption

        /// <summary>
        /// Main Encryption Method
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="salt"></param>
        /// <param name="salt2"></param>
        /// <param name="rounds"></param>
        /// <returns></returns>
        private static byte[] CrystallineEncrypt(byte[] data, byte[] key, byte[] salt, byte[] salt2, int rounds)
        {
            while (rounds >= 0)
            {
                data = ByByteEnc(data, key, salt, salt2);
                data = ByBitEnc(data, key, salt, salt2);
                data = ByByteEnc(data, key, salt, salt2);

                if (rounds-- == 0)
                    return data;
            }

            return null;
        }

        #endregion

        #region Decryption

        /// <summary>
        /// Main Decryption Method
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="salt"></param>
        /// <param name="salt2"></param>
        /// <param name="rounds"></param>
        /// <returns></returns>
        private static byte[] CrystallineDecrypt(byte[] data, byte[] key, byte[] salt, byte[] salt2, int rounds)
        {
            while (rounds >= 0)
            {
                data = ByByteDec(data, key, salt, salt2);
                data = ByBitDec(data, key, salt, salt2);
                data = ByByteDec(data, key, salt, salt2);

                if (rounds-- == 0)
                    return data;
            }

            return null;
        }

        #endregion

        #region Helper Functions

        #region By Bit Encrypt

        private static byte[] ByBitEnc(byte[] data, byte[] key, byte[] salt, byte[] salt2)
        {
            BitArray bitArray = new BitArray(data);

            bool isUp = false;
            int keyIndex = 0;
            int saltIndex = 0;
            int salt2Index = 0;

            //Move every bit in the entire file to a new location
            //As this progresses, most bits will be moved multiple times
            for (int i = 0; i < bitArray.Length; i++)
            {
                //Find new location for the bit and move it
                PerformBitShiftMod(ref bitArray, i, Shift(key[keyIndex++], salt[saltIndex++], salt2[salt2Index++]), isUp, false);

                //Toggle the direction of the next bit exchange
                isUp = isUp == false ? true : false;

                //Loop key and salt - if required
                if (keyIndex == key.Length)
                    keyIndex = 0;

                if (saltIndex == salt.Length)
                    saltIndex = 0;

                if (salt2Index == salt2.Length)
                    salt2Index = 0;
            }

            //Create byte array from bit array - Note endiness here (suitable for Intel)
            return BitArrayToByteArray(bitArray);          
        }

        #endregion

        #region By Byte Encrypt

        private static byte[] ByByteEnc(byte[] data, byte[] key, byte[] salt, byte[] salt2)
        {
            bool isUp = false;
            int keyIndex = 0;
            int saltIndex = 0;
            int salt2Index = 0;

            //Move every byte in the entire file to a new location
            //As this progresses, most bytes will be moved multiple times
            for (int i = 0; i < data.Length; i++)
            {
                //Find new location for the byte and move it
                PerformByteShiftMod(ref data, i, Shift(key[keyIndex++], salt[saltIndex++], salt2[salt2Index++]), isUp);

                //Toggle the direction of the next byte exchange
                isUp = isUp == false ? true : false;

                //Loop key and salt - if required
                if (keyIndex == key.Length)
                    keyIndex = 0;

                if (saltIndex == salt.Length)
                    saltIndex = 0;

                if (salt2Index == salt2.Length)
                    salt2Index = 0;
            }

            return data;
        }

        #endregion

        #region By Byte Decrypt

        private static byte[] ByByteDec(byte[] data, byte[] key, byte[] salt, byte[] salt2)
        {
            bool isUp = false;
            int keyIndex = 0;
            int saltIndex = 0;
            int salt2Index = 0;

            InitDecodeValues(data.Length, key.Length, ref keyIndex, salt.Length, ref saltIndex, salt2.Length, ref salt2Index, ref isUp);

            for (int i = data.Length - 1; i >= 0; i--)
            {
                int offset = Shift(key[keyIndex--], salt[saltIndex--], salt2[salt2Index--]);

                PerformByteShiftMod(ref data, i, offset, isUp);

                isUp = isUp == false ? true : false;

                if (keyIndex == -1)
                    keyIndex = key.Length - 1;

                if (saltIndex == -1)
                    saltIndex = salt.Length - 1;

                if (salt2Index == -1)
                    salt2Index = salt2.Length - 1;
            }

            return data;
        }

        #endregion

        #region By Bit Decrypt

        private static byte[] ByBitDec(byte[] data, byte[] key, byte[] salt, byte[] salt2)
        {
            BitArray plainData = new BitArray(data);

            bool isUp = false;
            int keyIndex = 0;
            int saltIndex = 0;
            int salt2Index = 0;

            int a = plainData.Count;
            int b = plainData.Length;
            InitDecodeValues(plainData.Count, key.Length, ref keyIndex, salt.Length, ref saltIndex, salt2.Length, ref salt2Index, ref isUp);

            for (int i = plainData.Count - 1; i >= 0; i--)
            {
                int offset = Shift(key[keyIndex--], salt[saltIndex--], salt2[salt2Index--]);

                PerformBitShiftMod(ref plainData, i, offset, isUp, true);

                isUp = isUp == false ? true : false;

                if (keyIndex == -1)
                    keyIndex = key.Length - 1;

                if (saltIndex == -1)
                    saltIndex = salt.Length - 1;

                if (salt2Index == -1)
                    salt2Index = salt2.Length - 1;
            }

            return BitArrayToByteArray(plainData);
        }

        #endregion

        #region Initialise Decode Values


        /// <summary>
        /// Set starting values in decode
        /// </summary>
        /// <param name="dataLength"></param>
        /// <param name="keyLength"></param>
        /// <param name="keyIndex"></param>
        /// <param name="saltLength"></param>
        /// <param name="saltIndex"></param>
        /// <param name="salt2Length"></param>
        /// <param name="salt2Index"></param>
        /// <param name="isUp"></param>
        private static void InitDecodeValues(int dataLength, int keyLength, ref int keyIndex, int saltLength, ref int saltIndex, int salt2Length, ref int salt2Index, ref bool isUp)
        {
            //Determine the direction data should be moved
            isUp = dataLength % 2 != 0 ? false : true;

            //Determine the starting key byte for decrypt
            for (int i = 0; i < dataLength - 1; i++)
            {
                keyIndex++;

                if (keyIndex == keyLength)
                    keyIndex = 0;
            }

            //Determine the starting salt byte for decrypt
            for (int i = 0; i < dataLength - 1; i++)
            {
                saltIndex++;

                if (saltIndex == saltLength)
                    saltIndex = 0;
            }

            //Determine the starting salt byte for decrypt
            for (int i = 0; i < dataLength - 1; i++)
            {
                salt2Index++;

                if (salt2Index == salt2Length)
                    salt2Index = 0;
            }
        }

        #endregion

        #region Shift Offset

        /// <summary>
        /// Calculate the new location of bit/byte
        /// </summary>
        /// <param name="key"></param>
        /// <param name="salt"></param>
        /// <param name="salt2"></param>
        /// <returns></returns>
        private static int Shift(byte key, byte salt, byte salt2)
        {
            return (int)key * (int)salt * (int)salt2;
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

        #region Convert Bit Array to Byte Array

        public static byte[] BitArrayToByteArray(BitArray bits)
        {
            byte[] bytes = new byte[bits.Length / 8];
            bits.CopyTo(bytes, 0);
            return bytes;
        }

        #endregion

        #endregion
    }
}
