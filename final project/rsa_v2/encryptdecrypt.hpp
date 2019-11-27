/*  Programmer:     Kyle Landrith
    Date Competed:  11/27/19
    Resources:      geeksforgeeks.com
                    https://brilliant.org/wiki/rsa-encryption/
                    https://simple.wikipedia.org/wiki/RSA_algorithm
                    https://don.p4ge.me/modular-exponentiation/programming
                    https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
    Description:    A class implementation and declaration to implement simple RSA
                    encryption.
*/

#pragma once

#include <ctime>
#include <string>
#include <sstream>
#include <iostream>

using std::rand;
using std::string;
using std::stringstream;
using std::hex;
using std::cout;

class RSA {
public:
  // constructor
  RSA(unsigned int msgsize) {
    msglength = msgsize;
    msg = new unsigned int[msglength];
    encryptedmsg = new unsigned int[msglength];
    decryptedmsg = new char[msglength];
  }
  
  // encryption function
  void encrypt(string message) {
    int index1, index2, eindex;
    // Seed the Random Number Generator
    srand(time(0));
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
    // convert the message from a string into an interger array
    // with type coercion
    for (int i = 0; i < msglength; i++) {
      msg[i] = message.at(i);
    }
    // encrypt the message and store it as an integer array
    for (int i = 0; i < msglength; i++) {
      encryptedmsg[i] = modExpo(msg[i], e, n);
    }
  }

  // decryption function
  void decrypt() {
    // decrypt the message and use type coercion to change from int to ASCII
    for (int i = 0; i < msglength; i++) {
      decryptedmsg[i] = modExpo(encryptedmsg[i], d, n);
    }
  }

  // function to return a string representing encrytped message
  string getEncrypted() {
    stringstream stream;
    for (int i = 0; i < msglength; i++) {
      stream << hex << encryptedmsg[i];
    }
    return stream.str();
  }

  // function to return a string representing decrypted message
  string getDecrypted() {
    stringstream stream;
    for (int i = 0; i < msglength; i++) {
      stream << decryptedmsg[i];
    }
    return stream.str();
  }

  // functions to return a string version of variables and keys
  long long unsigned int getP() {
    return p;
  }

  long long unsigned int getQ() {
    return q;
  }

  long long unsigned int getN() {
    return n;
  }

  long long unsigned int getE() {
    return e;
  }

  long long unsigned int getD() {
    return d;
  }

private:
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
    long long unsigned int modExpo(long long unsigned int base, long long unsigned int exp, long long unsigned int mod) {
      long long unsigned int remain;
      long long unsigned int result = 1;
      while (exp != 0) {
        remain = exp % 2;
        exp = exp / 2;
        if (remain == 1) result = (result * base) % mod;
        base = (base * base) % mod;
      }
      return result;
    }

    // function to find the modular multiplicative inverse d of e such that d*e = 1 mod phi
    // Iteratively uses the extended euclidean algorithm to
    // solves the following equation ax + by = gcd(a, b) for x
    // [note: assumes arguments passed are coprime]
    //
    long long unsigned int modInverse(long long unsigned int e, long long unsigned int phi) {
      long long unsigned int phi0 = phi;
      long long int y = 0, x = 1, quotient, temp;
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
    long long unsigned int gcd(long long unsigned int a, long long unsigned int b) {
      if (b == 0) return a;
      return gcd(b, a % b);
    }

  // variables needed for encryption/decryption
  long long unsigned int p, q, phi, n, e, d;
  int msglength;
  unsigned int primenumbers1[20] = {14503,
                                    14519,
                                    14533,
                                    14537,
                                    14543,
                                    14549,
                                    14551,
                                    14557,
                                    14561,
                                    14563,
                                    14591,
                                    14593,
                                    14621,
                                    14627,
                                    14629,
                                    14633,
                                    14639,
                                    14653,
                                    14657,
                                    14669};
  unsigned int primenumbers2[20] = {14813,
                                    14821,
                                    14827,
                                    14831,
                                    14843,
                                    14851,
                                    14867,
                                    14869,
                                    14879,
                                    14887,
                                    14891,
                                    14897,
                                    14923,
                                    14929,
                                    14939,
                                    14947,
                                    14951,
                                    14957,
                                    14969,
                                    14983};
  int earray[20] = {7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31,
                    33, 35, 37, 39, 41, 43, 45};
  unsigned int *msg;
  unsigned int *encryptedmsg;
  char *decryptedmsg;
};
