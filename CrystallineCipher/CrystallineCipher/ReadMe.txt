To Use:

Set the filenames and locations in Program.cs, build and run.


Important Note:
When examining randomness, if you are getting poor values, try changing the value
return by the method 'CrysallineDepth'.  This controls the number of rounds applied.
Crystalline must adapt to the nature of the input to preserve its random nature.
Adjust this value and inspect with ENT to observe the effects.



Useful Resources:

Source for truely random (atmospheric noise) bytes for passphrase and salt:
https://www.random.org/bytes/

-On Windows HxD Hex editor can be used to copy-and=paste the bytes directly
into empty text files.
http://mh-nexus.de/en/hxd/

Use ENT and HxD analysis to examine the output of the cipher text:
http://www.fourmilab.ch/random/



Split Keys/Salts:

By adding extra (key/salt) files to the input and shift calculation, it is possible to add
as many keys to the process as you want.  

Try it.
