This project requires that you have the NTL and GMP libraries installed.
Instructions at:
https://www.shoup.net/ntl/doc/tour-unix.html

and

https://www.shoup.net/ntl/doc/tour-win.html

This program is a simple RSA encryption program. It uses dyanmic arrays to encrypt a message of any length from console input. Key size is adjustable from 512 to 2048 bits. Uses PKCS #1 v1.5 style padding, however only one character is encrypted at a time and stored in a dynamic array. This adds to the computation time, but allows for an RSA algorithm that can encrypt a message larger than the value of p * q. 
