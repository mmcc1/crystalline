# Crystalline Cipher - An information theoretically secure symmetric cipher.

C# Reference Implementation

Project Overview
Cystalline Cipher is a symmetric cipher that performs transposition of bits and bytes, rather than hard to reverse mathematics. Designed to be as secure as a one-time pad, without a weakness due to the use of repeating keys, Crystalline has not shown a single break since the time of its initial release in May 2015.

Unlike many ciphers, Crystalline operates on an entire file and does not require padding operations or compression. Crystalline also employs arbitrary key sizes, although recommended practice is to use at minimum 16KB keys and salts (131072 bits) based upon truely random byte sources (such as atmospheric noise, etc.)


Please note that a recent senate draft bill, if it becomes law, would make Crystalline an illegal product within the US as it information theoretically secure (or unbreakable).
http://hosted.ap.org/dynamic/stories/U/US_CONGRESS_ENCRYPTION?SITE=AP&SECTION=HOME&TEMPLATE=DEFAULT&CTIME=2016-04-08-14-11-09

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

Theory of Operation

Crystalline employs information loss as the basis of its security. Information loss is a different process to intractable problems (one-way/trapdoor functions) used in ciphers such as RSA or Elliptic Curves. One-way functions assume that a given problem is difficult to reverse, whereas information loss removes the key by degrading its 'signal' in the ciphertext to a point beyond practical reconstruction. As such, information loss is a provable event and ultimately a more secure method for long term storage of ciphertexts.

In the context of Crystalline, information loss is achieved by shifting the location of data at both a binary and byte level based upon a value provided by the key and salt. As such, the end result is a cipher text that reflects the only the relationships found in the key and salt. If the key and salt is from a true random source, such as atmospheric noise or quantum fluctuations, then no relationship should be present in the location of bits and bytes in the ciphertext.

Thus, randomness in the ciphertext is a very strong indicator of strength in the cipher. That said, randomness means different things to different people. To some it is unpredictability, in the world of TRNGs it is unpredictability between a defined range over a period of time. This can lead to patterns in a TRNG output, a slight oscillation in the output, but not patterns that are usefully exploitable to recover the key/salt. These patterns can be captured in the output of Crystalline, most of the time the are obscured in the ciphertext, but again these are not usefully exploitable.

Overview of the Algorithm

In each round, Crystalline first swaps every bit in the file based upon values drawn from the key and salt. Before a bit is swapped, it is XOR'ed with the bit value 1. Then Crystalline erases that history by swapping every byte in the file, based upon values drawn from the key and salt.

Steps in a round:

Part A:
1. Load the plaintext, key and salt files into memory (circular buffer for each).
2. Calculate the location of the bits to switch based on the formula 'key*salt' (where both the key and salt are represented as integer values of a byte in the range 0-255)
3. Select the current bit index in the plaintext and XOR it with the value 1
4. Swap the bit with the bit identified in step 2.
5. Increment the index in the plaintext, key and salt (looping around the buffer necessary)
6. Repeat steps 2-5 inclusive until EOF (plaintext)

Part B:
1. Set indexes of the plaintext, key and salt to 0
2. Calculate the location of the bytes to switch based on the formula 'key*salt' (where both the key and salt are represented as integer values of a byte in the range 0-255)
3. Swap the byte with the byte identified in step 2.
4. Increment the index in the plaintext, key and salt (looping around the buffer necessary)
5. Repeats steps 2-4 inclusive until EOF (plaintext)

Information Loss

Three stages of information loss occur during each round:

1. We loss information on the key and salt by multiplying them
2. We loss information on the relationship between the bits and the data by swapping them and applying XOR.
3. We loss information of previous steps by swapping the bytes.

Loss of information in this way increases entropy with each round, until the dominating signal in the ciphertext are the relationships between the values in the salt and key. If no relationship exists in the salt and key (i.e. drawn from a TRNG), then there will be no relationships in the output. TRNGs tend to provide random numbers between an upper and lower limit (0-255 for a byte) evenly distributed. This can manifest as an oscillation in longterm frequency counts, so this order should dominate the output of Crystalline.


Frequently Asked Questions

Q: I read that Crystalline is an "obviously broken cipher" here: http://maldr0id.blogspot.com/2015/05/crystalline-cipher-and-cryptography.html

A: This article does not describe the Crystalline Cipher algorithm, it describes a pseudo-algorithm designed by the author. The author does clearly state that he knows little of Crytography, thus some mistakes are expected. Crystalline has never been broken, not even a single round has ever been reversed. Ask them to decrypt a file for you.

Q: I read that there is no need to introduce a salt here: http://maldr0id.blogspot.com/2015/05/crystalline-cipher-and-cryptography.html

A: Somewhat accurate. The purpose of a salt in a symmetric cipher is to ensure duplicate keys produce different cipher text. As such, a salt is more of a useful utility than anything to do with the cipher itself.

Q: This author feels there is a lot to infer, such as the language of the plain text. Is that true? so: http://maldr0id.blogspot.com/2015/05/crystalline-cipher-and-cryptography.html

A: No. Crystalline operates on a plain text much like a blockchain. The locations of bits and bytes are dependent on the preceeding bits or bytes. This means that to reverse the encryption process, we must undo all the changes that have occurred to arrive at the plain text. Statistical analysis of the cipher text won't reveal any useful patterns, simply because there is no mathematical pattern to be found in the first place. Bits and bytes are moved randomly driven by the key/salt, as long as this is random, there is no formula that can be applied to recovery beyond the algorithm. It is fair to say that Crystalline extends the concept of 'Nothing Up My Sleeve Numbers' to the entire algorithm.

Q: I read that at least n!/2^(n/2) keys will not encrypt the plaintext and it does not matter how many rounds are used. Is this true? http://maldr0id.blogspot.com/2015/05/crystalline-cipher-and-cryptography.html

A: The algorithm described is not Crystalline. The author made an error. There is a certain probability that a given bit or byte will remain unchanged in any given round, however, that is in no way a provable event. This is the key issue. Can we determine that the letter 'A', encoded in ASCII, at a given location is really A or not some randomly composed coincidence? No. Events like this are reduced as we move through each round, as the location changes result in different values for the bits/bytes to be exchanged with. Eventually, these 'stubborn' values are encrypted. This issue is not exploitable in any way and we recommend 5-10 rounds as a minimum.

Q: I read there is an issue with a large file filled with zeros that shows the output not to be random.

A: Crystalline transposes bits and bytes, a transposed file full of zeros can only ever be zeros. This is a test case that is applicable to algorithms that follow a different method of operation. In the context of Crystalline, it is a non-issue. Any non-random output cannot be used to decode the file as there is no mathematical relationship between the key/salt and data. The only mathematical relationship that exists is between the random sources (i.e key/salt) and the location of bits/bytes. This is something that is obscured beyond recovery through many rounds. Only the algorithm, with a proper key/salt, can restore the file back to its proper order.

Q: What anti-cryptanalysis features does Crystalline have?

A: Crystalline was developed to render both quantum and conventional computing attacks inert. With publications from Google on the quantum nature and speed of D-Wave http://www.techtimes.com/articles/114614/20151209/googles-d-wave-2x-quantum-computer-100-million-times-faster-than-regular-computer-chip.htm, it raises the possiblity that intelligence agencies have had quantum computing capabilites for quite some time. As a result most, if not all, forms of publically released encryption may be compromised as hard to solve mathematical problems, may be resolvable in near-real time. Crystalline does not employ hard to solve mathematics, it just randomly throws things around the place, thus Quantum computing is of limited use. As it also operates in a blockchain like manner, this limits the ability of conventional computing to attack the algorithm in a parallel fashion as it must be approached serially. Finally, plaintext attacks or statistical analysis will fail, as this requires a relationship between the ciphertext, plaintext and/or the algorithm. This relationship is entirely randomly (key/salt) requiring a unique solution for every ciphertext.

Q: The Crypto Forum Research Group at the IRTF was very hostile, some suggested it was broken. Is this true?

A: This is to be expected. All research is met with skepticism at first and nowhere is that greater than in the world of crypto, as the only expert in a new cipher is the creator. The resistance breaks down into multiple categories. Firstly, there are those who were applying their current knowledge to the new cipher, but were making mistakes and thought they saw weaknesses. Secondly, people connected with intel agencies who had gone into panic mode as they did not have an immediate solution. Something similar happened with Phil Zimmerman when he released PGP https://en.wikipedia.org/wiki/Phil_Zimmermann#Arms_Export_Control_Act_investigation and his cipher BassOmatic. Thirdly, people with lmited knowledge on the periphery jumping on trolling bandwagon. Out of these, the most forceful group will be those connected with intel agencies, as adoption of Crystalline means certain communications going dark with no hope of an advancement changing the situation. In addition, non-standard ciphers raise the associated costs of a break, as unique hardware must be developed. Most ciphers break with time, Crystalline does not.

Last edited May 3 at 11:28 AM by Marx_Bitware, version 6

