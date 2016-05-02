/* Crystalline Symmetric Cipher
 * Copyright: Mark McCarron (Marx Bitware) - 2016
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
    /// Crystalline Symmetric Cipher
    /// </summary>
    public static class Crystalline
    {
        #region Encrypt/Decrypt public methods

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="key">Key file data</param>
        /// <param name="salt">Salt file data</param>
        /// <param name="rounds">Number of rounds</param>
        /// <returns>Encrypted Data</returns>
        public static byte[] Encrypt(byte[] data, byte[] key, byte[] salt, int rounds)
        {
            return CrystallineEncrypt(data, key, salt, rounds);
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="data">Data to decrypt</param>
        /// <param name="key">Key file data</param>
        /// <param name="salt">Salt file data</param>
        /// <param name="rounds">Number of rounds</param>
        /// <returns>Decrypted Data</returns>
        public static byte[] Decrypt(byte[] data, byte[] key, byte[] salt, int rounds)
        {
            return CrystallineDecrypt(data, key, salt, rounds);
        }

        #endregion

        #region Encryption

        /// <summary>
        /// Main Encryption Method
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="key">Key file data</param>
        /// <param name="salt">Salt file data</param>
        /// <param name="rounds">Number of rounds</param>
        /// <returns>Encrypted Data</returns>
        private static byte[] CrystallineEncrypt(byte[] data, byte[] key, byte[] salt, int rounds)
        {
            while (rounds >= 0)
            {
                #region By Bit

                BitArray bitArray = new BitArray(data);

                bool isUp = false;
                int keyIndex = 0;
                int saltIndex = 0;

                //Move every bit in the entire file to a new location
                //As this progresses, most bits will be moved multiple times
                for (int i = 0; i < bitArray.Length; i++)
                {
                    //Find new location for the bit and move it
                    PerformBitShiftMod(ref bitArray, i, Shift(key[keyIndex++], salt[saltIndex++]), isUp, false);

                    //Toggle the direction of the next bit exchange
                    isUp = isUp == false ? true : false;

                    //Loop key and salt - if required
                    if (keyIndex == key.Length)
                        keyIndex = 0;

                    if (saltIndex == salt.Length)
                        saltIndex = 0;
                }

                //Create byte array from bit array - Note endiness here (suitable for Intel)
                byte[] cipherData = Helpers.BitArrayToByteArray(bitArray);

                #endregion

                #region By Byte

                isUp = false;
                keyIndex = 0;
                saltIndex = 0;

                //Move every byte in the entire file to a new location
                //As this progresses, most bytes will be moved multiple times
                for (int i = 0; i < cipherData.Length; i++)
                {
                    //Find new location for the byte and move it
                    PerformByteShiftMod(ref cipherData, i, Shift(key[keyIndex++], salt[saltIndex++]), isUp);

                    //Toggle the direction of the next byte exchange
                    isUp = isUp == false ? true : false;

                    //Loop key and salt - if required
                    if (keyIndex == key.Length)
                        keyIndex = 0;

                    if (saltIndex == salt.Length)
                        saltIndex = 0;
                }

                #endregion

                //If we are finished, return data, otherwise repeat
                //Every bit and byte has been moved, so looping the key and salt is secure
                //Each round smudges the data further until it is unrecoverable except for this algorithm
                if (rounds-- == 0)
                    return cipherData;
                else
                    data = cipherData;
            }

            return null;
        }

        #endregion

        #region Decryption

        /// <summary>
        /// Main Decryption Method
        /// </summary>
        /// <param name="data">Data to decrypt</param>
        /// <param name="key">Key file data</param>
        /// <param name="salt">Salt file data</param>
        /// <param name="rounds">Number of rounds</param>
        /// <returns>Decrypted Data</returns>
        private static byte[] CrystallineDecrypt(byte[] data, byte[] key, byte[] salt, int rounds)
        {
            while (rounds >= 0)
            {
                #region By Byte

                bool isUp = false;
                int keyIndex = 0;
                int saltIndex = 0;

                InitDecodeValues(data.Length, key.Length, ref keyIndex, salt.Length, ref saltIndex, ref isUp);

                for (int i = data.Length - 1; i >= 0; i--)
                {
                    int offset = Shift(key[keyIndex--], salt[saltIndex--]);

                    PerformByteShiftMod(ref data, i, offset, isUp);

                    isUp = isUp == false ? true : false;

                    if (keyIndex == -1)
                        keyIndex = key.Length - 1;

                    if (saltIndex == -1)
                        saltIndex = salt.Length - 1;
                }

                #endregion

                #region By Bit

                BitArray plainData = new BitArray(data);

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

                if (rounds-- == 0)
                    return Helpers.BitArrayToByteArray(plainData);
                else
                    data = Helpers.BitArrayToByteArray(plainData);
            }

            return null;
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

        #endregion
    }
}
