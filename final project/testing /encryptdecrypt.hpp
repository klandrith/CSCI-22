/*  Programmer:     Kyle Landrith
    Date Competed:  11/29/19
    Resources:      https://brilliant.org/wiki/rsa-encryption/
                    https://simple.wikipedia.org/wiki/RSA_algorithm
                    https://www.shoup.net/ntl/
                    https://www.geeksforgeeks.org/measure-execution-time-function-cpp/
                    https://www.includehelp.com/cpp-programs/find-total-number-of-bits-required-to-represent-a-number-in-binary.aspx
                    https://eli.thegreenplace.net/2019/rsa-theory-and-implementation/
    Description:    A class implementation and declaration to implement simple RSA
                    encryption on ASCII string input.
                    [note:] This project uses the NTL library for handling large
                    integer values and to perform various arithmetic operations
                    necessary for the RSA encryption/decryption algorithm.
*/

#pragma once

#include <string>
#include <sstream>
#include <NTL/ZZ.h>
#include <ctime>

using std::string;
using std::stringstream;
using std::stoi;
using std::rand;
using std::exception;
using namespace NTL;

class RSA {
public:
  // constructor
  RSA() {
    this->encryptedmsg = nullptr;
    this->decryptedmsg = nullptr;
    this->charDecryptMsg = nullptr;
  }

  // destructor
  ~RSA() {
    delete []encryptedmsg;
    delete []decryptedmsg;
    delete []charDecryptMsg;
  }

  // key generation function
  void generateKeys(int keylength) {
    // set bit length for prime numbers and error rate 2^(-error)
    // error rate is upper limit that generated numbers are not actually prime
    long primelength;
    primelength = keylength;
    long error;
    error = 80;
    this->p = 1;
    this->q = 1;
    // generate 1024 bit primes that are different
    while (p == q) {
      this->p = GenGermainPrime_ZZ(primelength, error);
      this->q = GenGermainPrime_ZZ(primelength, error);
    }
    // seed pseudo random number generators
    srand(time(0));
    ZZ seed;
    seed = rand() % 999999;
    void SetSeed(const ZZ& seed);
    // assign n and phi values
    this->n = this->p * this->q;
    this->phi = (this->p - 1) * (this->q - 1);
    // set bit length for e generation
    long elength;
    elength = 64;
    // test if e and phi are coprime, if not change value of e until they are
    while (true) {
      this->e = RandomLen_ZZ(elength);
      if (GCD(this->e, this->phi) == 1 && this->e > 65535) break;
    }
    // get value for d (de = 1 mod phi)
    this->d = InvMod(this->e, this->phi);
  }

  void EncryptRSA(string message) {
    this->msglength = message.size();
    if (this->encryptedmsg != nullptr) {
      delete []encryptedmsg;
      delete []decryptedmsg;
      delete []charDecryptMsg;
    }
    this->encryptedmsg = new ZZ[this->msglength];
    this->decryptedmsg = new ZZ[this->msglength];
    this->charDecryptMsg = new char[this->msglength];
    // loop through entire message and encrypt each character
    for (int i = 0; i < this->msglength; i++) {
      // create instance of stringstream
      stringstream stream;
      // seed RNG
      srand(time(0));
      ZZ seed;
      seed = rand() % 555;
      void SetSeed(const ZZ& seed);
      unsigned int asciiValue = message.at(i);
      unsigned int keyLen = (countBits(n) + 7) / 8;
      // add padding to message
      // eblock = 01 || 02 || random padding || 00 || message
      unsigned int psLen = keyLen - (countBits(asciiValue) / 8) - 3;
      unsigned char eblock[keyLen];
      eblock[0] = 0x01;
      eblock[1] = 0x02;
      srand(time(0));
      // fill PS
      for (int j = 2; j < 2 + keyLen; j++) {
        ZZ random = RandomLen_ZZ(255);
        stringstream stream;
        stream << random;
        unsigned char ran;
        stream >> ran;
        eblock[j] = ran;
        // clear stream for next round of for loop
        stream.ignore(stream.str().size());
      }
      eblock[2 + psLen] = 0x00;
      // copy the current ascii character value into last block
      eblock[3 + psLen] = asciiValue;
      // loop through and output contents of array into stream
      for (int j = 0; j <= keyLen; j++) {
        unsigned int tempint = eblock[j];
        stream << tempint;
      }
      // dump contents of stream into ZZ object
      ZZ tempZZ;
      stream >> tempZZ;
      // encrypt current msgnum
      ZZ encrypted = PowerMod(tempZZ, e, n);
      this->encryptedmsg[i] = encrypted;
      // clear stream for next round of for loop
      stream.ignore(stream.str().size());
      void clear(ZZ& tempZZ);
    }
  }

  // encryption function
  ZZ encrypt(ZZ mnum) {
    return PowerMod(mnum, this->e, this->n);
  }

  // decryption function
  void DecryptRSA() {
    for (int i = 0; i < this->msglength; i++) {
      decryptedmsg[i] = PowerMod(this->encryptedmsg[i], d, n);
      stringstream stream;
      stream << decryptedmsg[i];
      string tempstring = stream.str();
      //testing code
      //std::cout << "\nDecrypted raw:\n" << tempstring << std::endl;
      if (tempstring.at(0) != '1') {
        throw std::invalid_argument("FIRST BLOCK OF PADDING DOES NOT MATCH!!!");
      }
      if (tempstring.at(1) != '2') {
        throw std::invalid_argument("SECOND BLOCK OF PADDING DOES NOT MATCH!!!");
      }
      // clear stream for next round of for loop
      stream.ignore(stream.str().size());
    }
    for (int i = 0; i < this->msglength; i++) {
      stringstream stream;
      string temp;
      stream << decryptedmsg[i];
      stream >> temp;
      string decryptedMsg = temp.substr(temp.size() - 3, string::npos);
      charDecryptMsg[i] = stoi(decryptedMsg);
      // clear stream for next round of for loop
      stream.ignore(stream.str().size());
    }
  }

  // function to return a string representing encrytped message
  string getEncrypted() {
    stringstream stream;
    for (int i = 0; i < this->msglength; i++) {
      stream << this->encryptedmsg[i];
    }
    return stream.str();
  }

  // function to return a string representing decrypted message
  string getDecrypted() {
    stringstream stream;
    for (int i = 0; i < this->msglength; i++) {
      stream << this->charDecryptMsg[i];
    }
    return stream.str();
  }

  // functions to return a string version of variables and keys
  string getP() {
    stringstream stream;
    stream << this->p;
    return stream.str();
  }

  string getQ() {
    stringstream stream;
    stream << this->q;
    return stream.str();
  }

  string getN() {
    stringstream stream;
    stream << this->n;
    return stream.str();
  }

  string getE() {
    stringstream stream;
    stream << this->e;
    return stream.str();
  }

  string getD() {
    stringstream stream;
    stream << this->d;
    return stream.str();
  }

  // function to count the bits in encryption keys
  template <typename T>
  int countBits(T value) {
    int count = 0;
    T temp = value;
    // While loop will run until we get temp = 0
    while(temp > 0) {
      count++;
      // We are shifting n to right by 1
      // place as explained above
      temp = temp >> 1;
  	}
  	return count;
  }

  // function to return bit length of N key
  int keyLength() {
    return countBits(this->n);
  }

private:
  // variables needed for encryption/decryption
  ZZ p, q, phi, n, e, d;
  unsigned int msglength;

  ZZ *encryptedmsg;
  ZZ *decryptedmsg;
  char *charDecryptMsg;
};
