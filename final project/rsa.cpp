/*  Programmer:     Kyle Landrith
    Date Competed:  11/23/19
    Resources:      geeksforgeeks.com
                    https://brilliant.org/wiki/rsa-encryption/
                    https://simple.wikipedia.org/wiki/RSA_algorithm
                    https://don.p4ge.me/modular-exponentiation/programming
                    https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
    Description:    A simple program to perform RSA encryption on a string message
                    entered through console input. Generates random keys each time
                    the program is ran. May possibly adapt it in the future to work
                    with file input and file output, as well as larger sized prime
                    numbers for generating better keys.
*/
#include <iostream>
#include <ctime>
#include <string>
#include "CinReader.h"

using std::cin;
using std::cout;
using std::rand;
using std::string;
using std::getline;
using std::hex;

unsigned int modExpo(unsigned int a, unsigned int b, unsigned int n);
unsigned int modInverse(unsigned int e, unsigned int phi);
unsigned int gcd(unsigned int a, unsigned int b);
void ClearScreen();

int main() {
  unsigned int p, q, phi, n, e, d;
  int index1, index2, eindex;
  int selection = 0;
  string message;
  CinReader reader;
  int primenumbers1[20] = {101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
                          151, 157, 163, 167, 173, 179, 181, 191, 193, 197};
  int primenumbers2[20] = {211, 223, 227, 229, 233, 239, 241, 251, 257, 263,
                          269, 271, 277, 281, 283, 293, 307, 311, 313, 317};
  int earray[20] = {3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31,
                    33, 35, 37, 39, 41};
  do {
    // Seed the Random Number Generator
    srand(time(0));
    ClearScreen();
    index1 = rand() % 20;
    index2 = rand() % 20;
    p = primenumbers1[index1];
    q = primenumbers2[index2];
    n = p * q;
    phi = (p - 1) * (q - 1);
    // test if e and phi are coprime, if not change value of e until they are
    while (true) {
      eindex = rand() % 20;
      e = earray[eindex];
      if (gcd(e, phi) == 1) break;
    }
    d = modInverse(e, phi);

    cout << "Random prime numbers have been selected for use in\n"
         << "generating the public and private keys. p: " << p << ", q: " << q <<"\n"
         << "An odd number between 3 and 41 that is coprime to\n"
         << "(p - 1) * (q - 1) has been selected for the value of e.\n"
         << "\nPublic key is: (n: " << n << ", e: " << e << ")\n"
         << "Private key is: (n: " << n << ", d: " << d << ")\n"
         << "\nEnter the message to encrypt:\n";
    getline(cin, message);

    int msglength = message.size();
    int msg[msglength];
    unsigned int encryptedmsg[msglength];
    char decryptedmsg[msglength];
    // convert the message from a string into an interger array
    // with type coercion
    for (int i = 0; i < msglength; i++) {
      msg[i] = message.at(i);
    }
    // encrypt the message and store it as an integer array
    for (int i = 0; i < msglength; i++) {
      encryptedmsg[i] = modExpo(msg[i], e, n);
    }
    // output the contents of the encrypted message array
    cout << "\nEncrypted messaged is:\n";
    for (int i = 0; i < msglength; i++) {
      cout << hex << encryptedmsg[i];
    }
    cout << "\n";
    // decrypt the message and use type coercion to change from int to ASCII
    for (int i = 0; i < msglength; i++) {
      decryptedmsg[i] = modExpo(encryptedmsg[i], d, n);
    }
    // output contents of decrypted message
    cout << "\nDecrypted message is: \n";
    for (int i = 0; i < msglength; i++) {
      cout << decryptedmsg[i];
    }
    cout << "\n\nEnter 0 to exit, 1 to encrypt another message: ";
    selection = reader.readInt(0, 1);
  } while(selection == 1);
 return 0;
}

// function to perform modular exponentiation
// modular exponentiation splits the exponents into component parts,
// ex: 2^90 = 2^50 * 2^40 so that we avoid overrunning the register size when calculating
// even moderately large exponents such as is done when performing RSA encryption prior
// to calling modulus on them for encryption/decryption. Without this, only small
// prime values may be used to generate the keys. This implementation converts the exponent
// into a binary and then performs a series of arithmetic on the base to arrive at the result
//
// ex: 2^2 mod 3
// result = 1
// (first loop)
// remain = 2 % 2 = 0
// exp = 2 / 2 = 1
// if (remain == 1) result = (1 * 2) % 3 [FALSE]
// base = base^2 % 3 = 1
// (second loop)
// remain = 1 % 2 = 1
// exp = 1 / 2 = 0
// if (remain == 1) result = (1 * 1) % 3 = 1
// end of loop [exp is 0]
// return result [1]
//
unsigned int modExpo(unsigned int base, unsigned int exp, unsigned int mod) {
  int remain;
  unsigned int result = 1;
  while (exp != 0) {
    remain = exp % 2;
    exp = exp / 2;
    if (remain == 1) result = (result * base) % mod;
    base = (base * base) % mod;
  }
  return result;
}

// function to find the modular multiplicative inverse d of e such that d*e = 1 mod phi
// Iteratively uses the extended euclidean algorithm.
// solves the following equation ax + by = gcd(a, b)
// [note: assumes arguments passed are coprime]
//
unsigned int modInverse(unsigned int e, unsigned int phi) {
  unsigned int phi0 = phi;
  int y = 0, x = 1, quotient, temp;
  if (phi == 1) return 0;
  while (e > 1) {
    quotient = e / phi;
    temp = phi;
    // phi is remainder now, process same as
    // Euclid's algorithm
    phi = e % phi;
    e = temp;
    temp = y;
    // Update y and x
    y = x - quotient * y;
    x = temp;
  }
  // Make x positive
  if (x < 0) x += phi0;
  return x; // value of d for private key
}

// function to find the greatest common denominator of two integers
// using euclides algorithm
unsigned int gcd(unsigned int a, unsigned int b) {
  if (b == 0) return a;
  return gcd(b, a % b);
}

// function to clear screen
void ClearScreen() {
#ifdef _WIN32
  std::system("cls");
#else
  // Assume POSIX
  std::system("clear");
#endif
}
