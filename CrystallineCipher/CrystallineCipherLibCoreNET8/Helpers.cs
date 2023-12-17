using System.Collections;

namespace CrystallineCipherLib
{
    public static class Helpers
    {
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
    }
}
