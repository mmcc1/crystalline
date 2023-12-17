# Crystalline Cipher 1, 2 & 3

A set of information theoretically secure symmetric ciphers designed to thwart analysis or cracking by Quantum computing. C# (Framework 4.8, .NET Standard 2.0 and NET8) Reference Implementation.

Project Overview

Cystalline Cipher is a symmetric cipher series which performs transposition of bits and bytes, rather than hard to reverse mathematics. Unlike many ciphers, Crystalline operates on an entire file and does not require padding operations. Compression of plaintext is recommended. Crystalline employs arbitrary key sizes, although recommended practice is to use at minimum 32KB keys and salts based upon truely random byte sources (such as atmospheric noise, etc.)

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
