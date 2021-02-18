# Crystalline Cipher 1 & 2

- A set of information theoretically secure symmetric ciphers.

C# Reference Implementation

Project Overview
Cystalline Cipher is a symmetric cipher that performs transposition of bits and bytes, rather than hard to reverse mathematics. There are two versions, with the second having an expanded transposition area.  No break has ever been revealed since its creation in May 2015.

Unlike many ciphers, Crystalline operates on an entire file and does not require padding operations. Compression is recommended in certain circumstances and output should always be inspected.  Crystalline employs arbitrary key sizes, although recommended practice is to use at minimum 32KB keys and salts based upon truely random byte sources (such as atmospheric noise, etc.)


Theory of Operation

Crystalline employs information loss as the basis of its security. Information loss is a different process to intractable problems (one-way/trapdoor functions) used in ciphers such as RSA or Elliptic Curves. One-way functions assume that a given problem is difficult to reverse, whereas information loss removes the data by degrading its 'signal' in the ciphertext to a point beyond practical reconstruction.


Overview of the Algorithm

In each round, Crystalline first swaps every bit in the file based upon values drawn from the key and salt. Before a bit is swapped, it is XOR'ed with the bit value 1. Then Crystalline erases that history by swapping every byte in the file, based upon values drawn from the key and salt.

Steps in a round:

Part A:
1. Load the plaintext, key and salt files into memory (circular buffer for each).
2. Calculate the location of the bits to switch based on the formula 'key*salt' (key*salt*salt2 in Crystalline2)
3. Select the current bit index in the plaintext and XOR it with the value 1
4. Swap the bit with the bit identified in step 2.
5. Increment the index in the plaintext, key and salt (looping around the buffer necessary)
6. Repeat steps 2-5 inclusive until EOF (plaintext)

Part B:
1. Set indexes of the plaintext, key and salt to 0
2. Calculate the location of the bytes to switch based on the formula 'key*salt' (key*salt*salt2 in Crystalline2)
3. Swap the byte with the byte identified in step 2.
4. Increment the index in the plaintext, key and salt (looping around the buffer necessary)
5. Repeats steps 2-4 inclusive until EOF (plaintext)


Information Loss

Three stages of information loss occur during each round:

1. We loss information on the key and salts
2. We loss information on the data.
3. We loss information of previous steps.

Loss of information in this way increases entropy with each round, until the dominating signal in the ciphertext are the relationships between the random values in the salts and key.


Frequently Asked Questions

Q: I read that Crystalline is an "obviously broken cipher":

A: It has quirks, but nothing which has been demonstrated as exploitable. The acid is test is to decrypt a file and that, so far, has never been achieved.

Q: I read that there is no need to introduce a salt:

A: Somewhat accurate. The purpose of a salt in a symmetric cipher is to ensure duplicate keys produce different cipher text. As such, a salt is more of a useful utility than anything to do with the cipher itself.

Q: This author feels there is a lot to infer, such as the language of the plain text. Is that true?

A: It has never been demonstrated to be accurate.  Further, it has never been proven to provide a practical break.

Q: I read that at least n!/2^(n/2) keys will not encrypt the plaintext and it does not matter how many rounds are used. Is this true?

A: There is a certain probability that a given bit or byte will remain unchanged in any given round, however, that is in no way a provable event. Events like this are reduced as we move through each round, as the location changes result in different values for the bits/bytes to be exchanged with. Eventually, these 'stubborn' values are encrypted. This issue is not exploitable in any way and we recommend 5-10 rounds as a minimum.

Q: I read there is an issue with a large file filled with zeros that shows the output not to be random.

A: It will leave a signature weave, highlighting that the region is full of zeros.  Compression with Rar is recommended if patterns are observed.  It has never been proven to provide a practical break.

Q: What anti-cryptanalysis features does Crystalline have?

A: Crystalline does not employ hard to solve mathematics, it just randomly throws things around the place, thus Quantum computing is of limited use. As it also operates in a blockchain like manner, this limits the ability of conventional computing to attack the algorithm in a parallel fashion as it must be approached serially. Finally, plaintext attacks or statistical analysis will fail, as this requires a relationship between the ciphertext, plaintext and/or the algorithm. This relationship is entirely randomly (key/salts) requiring a unique solution for every ciphertext.

Q: The Crypto Forum Research Group at the IRTF was very hostile, some suggested it was broken. Is this true?

A: This is to be expected. All research is met with skepticism at first, as the only expert in a new cipher is the creator. The resistance breaks down into multiple categories. Firstly, there are those who were applying their current knowledge to the new cipher, but were making mistakes and thought they saw weaknesses. Secondly, people connected with intel agencies who had gone into panic mode as they did not have an immediate solution. Something similar happened with Phil Zimmerman when he released PGP https://en.wikipedia.org/wiki/Phil_Zimmermann#Arms_Export_Control_Act_investigation and his cipher BassOmatic. Thirdly, people with lmited knowledge on the periphery jumping on trolling bandwagon.

Source for truely random (atmospheric noise) bytes for passphrase and salt:
https://www.random.org/bytes/

The source is available under numerous licenses:

* Apache - http://www.apache.org/licenses/LICENSE-2.0
* BSD 3-Clause - https://opensource.org/licenses/BSD-3-Clause
* BSD 2-Clause - https://opensource.org/licenses/BSD-2-Clause
* WTFPL - http://www.wtfpl.net/about/
* MIT - https://opensource.org/licenses/MIT
* LGPL v3.0 - http://www.gnu.org/licenses/lgpl-3.0.en.html
* LGPL v2.1 - http://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html
* GPL v3.0 - http://www.gnu.org/licenses/gpl-3.0.en.html
* GPL v2.0 - http://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html 
