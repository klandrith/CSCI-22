This project requires that you have the NTL and GMP libraries installed.
Instructions at:
https://www.shoup.net/ntl/doc/tour-unix.html and https://www.shoup.net/ntl/doc/tour-win.html

This program is a simple RSA encryption program that takes console input and performs RSA encryption on the input, displays various facts about the current state of the program, the encrypted message, and finally the decrypted message. It uses vectors to encrypt messages of any length [tested with over 200,000 random characters] from console input. Key size is 2048 bits. Uses PKCS #1 v1.5 padding, up to 64 characters are encrypted at a time and each encrypted block is stored in a vector.
