To Use:
Set the filenames and locations in Program.cs, build and run.


Important Note:

In some circumstances (like a file of zeros) Crystalline can create a weave pattern
in the output.  While this does not reveal the key/salts, it does create a signature.
It is recommended that some files be compressed and the output checked with ENT or a
2D analysis in R.


Useful Resources:

Source for truely random (atmospheric noise) bytes for passphrase and salt:
https://www.random.org/bytes/

-On Windows HxD Hex editor can be used to copy-and-paste the bytes directly
into empty text files.
http://mh-nexus.de/en/hxd/

Use ENT and HxD analysis to examine the output of the cipher text:
http://www.fourmilab.ch/random/
Command Line - "ent ciphertext.txt"


R Code

2D Analysis

wh <- c(464, 464) #Change to the nearest square of file size
v <- readBin("0.cle", what = "integer", n = prod(wh), size = 1, signed = FALSE, endian = "little")

tiff("output.tif", width=wh[1], height=wh[2])
par(c(0,0,0,0))
image(matrix(v, wh[1], wh[2])[wh[1]:1,], useRaster = TRUE, col = grey.colors(256))
dev.off()



3D Analysis (Requires RGL)

wh <- c(2048, 2048) #Change to the nearest square of file size in bytes
v <- readBin("0.cle", what = "integer", n = prod(wh), size = 1, signed = FALSE, endian = "little")
x <- 1:2048 #Change to the nearest square of file size in bytes
y <- 1:2048 #Change to the nearest square of file size in bytes
z <- v[1:4194304] #Change to whatever the square of wh[1] is.

open3d()
rgl.surface(x, y, z, col="skyblue")


