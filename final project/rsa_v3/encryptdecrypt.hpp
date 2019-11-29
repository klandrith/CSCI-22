/*  Programmer:     Kyle Landrith
    Date Competed:  11/29/19
    Resources:      https://brilliant.org/wiki/rsa-encryption/
                    https://simple.wikipedia.org/wiki/RSA_algorithm
                    https://www.shoup.net/ntl/
                    https://www.geeksforgeeks.org/measure-execution-time-function-cpp/
                    https://www.includehelp.com/cpp-programs/find-total-number-of-bits-required-to-represent-a-number-in-binary.aspx
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
using namespace NTL;

class RSA {
public:
  // constructor
  RSA(unsigned int msgsize) {
    // initialize dynamic arrays and set msglength for array sizes
    this->msglength = msgsize;
    this->msg = new ZZ[msglength];
    this->encryptedmsg = new ZZ[msglength];
    this->decryptedmsg = new char[msglength];
  }

  // destructor
  ~RSA() {
    delete []msg;
    delete []encryptedmsg;
    delete []decryptedmsg;
  }

  // encryption function
  void encrypt(string message) {
    long primelength;
    primelength = 1024;
    long error;
    error = 80;
    this->p = 1;
    this->q = 1;
    // generate 1024 bit primes that are different
    while (p == q) {
      this->p = GenGermainPrime_ZZ(primelength, error);
      this->q = GenGermainPrime_ZZ(primelength, error);
    }
    // seed pseudo random number generator
    srand(time(0));
    ZZ seed;
    seed = rand() % 9999999 + 1;
    void SetSeed(const ZZ& seed);
    // assign n and phi values
    this->n = this->p * this->q;
    this->phi = (this->p - 1) * (this->q - 1);
    ZZ maxe;
    maxe = 9999;
    // test if e and phi are coprime, if not change value of e until they are
    while (true) {
      this->e = RandomBnd(maxe);
      if (GCD(this->e, this->phi) == 1 && this->e > 7) break;
    }
    // get value for d (de = 1 mod phi)
    this->d = InvMod(this->e, this->phi);
    // convert the message from a string into a ZZ array
    // with type coercion
    for (int i = 0; i < this->msglength; i++) {
      this->msg[i] = message.at(i);
    }
    // encrypt the message and store it as an integer array
    for (int i = 0; i < this->msglength; i++) {
      ZZ intmsg;
      intmsg = this->msg[i];
      // call modular exponention function to encrypt message
      this->encryptedmsg[i] = PowerMod(intmsg, this->e, this->n);
    }
  }

  // decryption function
  void decrypt() {
    for (int i = 0; i < this->msglength; i++) {
      string str;
      stringstream stream;
      // call modular exponention function to decrypt message
      stream << PowerMod(this->encryptedmsg[i], this->d, this->n);
      //debugging code
      try {
        this->decryptedmsg[i] = stoi(stream.str());
      } catch (const std::exception &e) {
        std::cout << e.what() << std::endl;
        std::cout << "current value of string stream to be stoi'd is: " << stream.str() << std::endl;
      }
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
      stream << this->decryptedmsg[i];
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
int countBits() {
  int count = 0;
  ZZ temp = this->n;
  // While loop will run until we get temp = 0
  while(temp > 0) {
    count++;
    // We are shifting n to right by 1
    // place as explained above
    temp = temp >> 1;
	}
	return count;
}

private:
  // variables needed for encryption/decryption
  ZZ p, q, phi, n, e, d;
  unsigned int msglength;
  ZZ *msg;
  ZZ *encryptedmsg;
  char *decryptedmsg;
};
