
/*  Programmer:     Kyle Landrith
    Date Competed:  11/29/19
    Resources:      https://brilliant.org/wiki/rsa-encryption/
                    https://simple.wikipedia.org/wiki/RSA_algorithm
                    https://en.wikipedia.org/wiki/Modular_exponentiation#Pseudocode
                    https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
                    https://www.includehelp.com/cpp-programs/find-total-number-of-bits-required-to-represent-a-number-in-binary.aspx
    Description:    A class implementation and declaration to implement simple RSA
                    encryption.
                    [note: prime numbers are originally stored in a string array
                    because the ttmath library will not allow initializing integers
                    to that large of a number, however it will support it, so it has
                    to be assigned as a string and then converted]
*/

#pragma once

//#define NDEBUG
#include <string>
#include <sstream>
#include <cassert>
#include <NTL/ZZ.h>

using std::string;
using std::stringstream;
using std::stoi;
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
    long l;
    l = 1024;
    long error;
    error = 80;
    this->p = GenGermainPrime_ZZ(l, error);
    this->q = GenGermainPrime_ZZ(l, error);
    ZZ seed;
    seed = 555;
    void SetSeed(const ZZ& seed);
  }

  // destructor
  ~RSA() {
    delete []msg;
    delete []encryptedmsg;
    delete []decryptedmsg;
  }

  // encryption function
  void encrypt(string message) {
    this->n = this->p * this->q;
    this->phi = (this->p - 1) * (this->q - 1);
    // test if e and phi are coprime, if not change value of e until they are
    ZZ maxe;
    maxe = 9999;
    while (true) {
      this->e = RandomBnd(maxe);
      if (GCD(this->e, this->phi) == 1 && this->e > 7) break;
    }
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
      this->encryptedmsg[i] = PowerMod(intmsg, this->e, this->n);
    }
  }

  // decryption function
  void decrypt() {
    for (int i = 0; i < this->msglength; i++) {
      string str;
      stringstream stream;
      stream << PowerMod(this->encryptedmsg[i], this->d, this->n);
      //testing code
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

int countBits() {
  int count = 0;
  ZZ temp = this->n;
  // While loop will run until we get n = 0
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
  int msglength;
  ZZ *msg;
  ZZ *encryptedmsg;
  char *decryptedmsg;
};
