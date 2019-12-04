/*  Programmer:     Kyle Landrith
    Date Competed:  12/4/19
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
#include <vector>

using std::string;
using std::stringstream;
using std::stoi;
using std::rand;
using std::exception;
using std::vector;
using std::hex;
using std::cout;
using std::endl;
using namespace NTL;

class RSA {
public:
  // constructor
  RSA() {
    // seed RNG
    srand(time(0));
    // seed RNG
    ZZ seed;
    seed = rand() % 255;
    void SetSeed(const ZZ& seed);
  }

  // destructor
  ~RSA() {
  }

  // key generation function
  void generateKeys() {
    this->e = 65537;
    long primelength;
    primelength = 1024;
    long error;
    error = 80;
    this->p = GenGermainPrime_ZZ(primelength, error);
    this->q = GenGermainPrime_ZZ(primelength, error);
    // assign n and phi values
    this->n = this->p * this->q;
    this->phi = (this->p - 1) * (this->q - 1);
    // keep generating primes under
    while (GCD(this->e, this->phi) != 1 && this->p == this->q) {
      // set bit length for prime numbers and error rate 2^(-error)
      // error rate is upper limit that generated numbers are not actually prime
      // generate 1024 bit primes that are different
      this->p = GenGermainPrime_ZZ(primelength, error);
      this->q = GenGermainPrime_ZZ(primelength, error);
      // assign n and phi values
      this->n = this->p * this->q;
      this->phi = (this->p - 1) * (this->q - 1);
    }
    // get value for d (de = 1 mod phi)
    this->d = InvMod(this->e, this->phi);
    // set keyLen for length of encrypted blocks (minus 1 byte to make sure
    // that encrypted block is always less than N or D values, otherwise
    // powerMod will throw an error)
    this->keyLen = ((countBits(n) + 7) / 8) - 1;
  }

  // encryption function
  void EncryptRSA(string message) {
    // set msglength and clear the vector if it was previously filled
    this->msglength = message.size();
    if (this->encryptedmsg.size() != 0) {
      this->encryptedmsg.clear();
    }
    // set loopcycles with ceiling value to capture chars after incremements of four chars
    this->loopcycles = ceil(this->msglength / 32);
    // loop through entire message and encrypt every one to four characters max
    unsigned int pos = 0;
    string stringvalue;
    ZZ tempZZ;
    for (int a = 0; a < this->loopcycles; a++) {
      stringvalue = message.substr(pos, 32);
      unsigned int mlength = stringvalue.size();
      // create vectpr for storing blocks
      vector<unsigned char> eblock(this->keyLen);
      // set padding length
      unsigned int psLen = (keyLength() / 8) - (1 * mlength) - 3;
      // add padding to message
      // eblock = 01 || 02 || random padding || 00 || message
      eblock[0] = 0x00;
      eblock[1] = 0x02;
      ZZ ran;
      long limit = 255;
      unsigned int psTemp;
      // fill PS with random numbers
      for (int j = 2; j < psLen; j++) {
        ran = RandomLen_ZZ(limit);
        conv(psTemp, ran);
        eblock[j] = psTemp;
      }
      // add index padding block for locating message in decrypted block
      eblock[2 + psLen] = 0x00;
      // insert ascii values depending on how many characters in substring
      AddMsgToBlock(eblock, stringvalue);
      // create temporary char array to pass to ZZFromBytes function and
      // pass in values from eblock vector
      unsigned char tempblock[eblock.size()];
      for (int l = 0; l < eblock.size(); l++) {
        tempblock[l] = eblock.at(l);
      }
      unsigned char *ptr;
      ptr = tempblock;
      long bytelength = this->keyLen;
      // convert from byte block (unsigned char array) to ZZ
      tempZZ = ZZFromBytes(ptr, bytelength);
      // encrypt byte converted ZZ and store
      this->encryptedmsg.push_back(PowerMod(tempZZ, e, n));
      // increment pos counter by four to capture next four characters (or less)
      pos += 32;
    }
  }

  void AddMsgToBlock(vector<unsigned char> &eblock, string stringvalue) {
    unsigned int counter = stringvalue.size();
    for (int i = 0; i < stringvalue.size(); i++) {
      eblock[eblock.size() - counter] = stringvalue.at(i);
      counter--;
    }
  }

  // decryption function
  void DecryptRSA() {
    // clear decrypted message string
    this->decryptedmessage = "";
    for (int i = 0; i < this->loopcycles; i++) {
      // decrypt raw ZZ
      ZZ rawdecrypt = PowerMod(this->encryptedmsg[i], d, n);
      long bytelength = this->keyLen;
      // create char array for decrypted and padded msg
      unsigned char ublock[this->keyLen];
      unsigned char *ptr;
      ptr = ublock;
      // convert from raw ZZ back to byte block (unsigned char array)
      BytesFromZZ(ptr, rawdecrypt, bytelength);
      // check if msg length is of correct size and that initial padding blocks
      // are intact
      if (this->keyLen != sizeof (ublock)) {
        throw std::logic_error("ERROR!!! KEY LENGTH DOES NOT EQUAL MSG LENGTH");
      }
      // test first and second block of bytes for correct padding scheme
      if (ublock[0] != 0x00) {
        throw std::logic_error("ERROR!!! EXPECTED 0x00 AT FIRST BLOCK!!!");
      }
      if (ublock[1] != 0x02) {
        throw std::logic_error("ERROR!!! EXPECTED 0x02 AT FIRST BLOCK!!!");
      }
      // search ublock array for 0x00 padding byte
      unsigned int index;
      for (int j = 0; j < this->keyLen; j++) {
        // cycle until last 0 block is found and set index as + 1
        if (ublock[j] == 0x00) index = j + 1;
      }
      // create temp vector to pass in characters via for loop
      vector<unsigned char> temp(this->keyLen - index);
      for (int j = 0; j < temp.size(); j++) {
        temp[j] = ublock[j + index];
      }
      // extract characters from vector and append to decryptedmessage string
      for (int k = 0; k < temp.size(); k++) {
        this->decryptedmessage += temp[k];
      }
    }
  }

  // function to return a string representing encrytped message in hex
  string getEncrypted() {
    stringstream stream;
    for (int i = 0; i < this->encryptedmsg.size(); i++) {
      unsigned int temp;
      conv(temp, this->encryptedmsg[i]);
      stream << hex << temp;
    }
    return stream.str();
  }

  // function to return a string representing decrypted message
  string getDecrypted() {
    return this->decryptedmessage;
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

  // function to count bits
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
  double msglength;
  unsigned int keyLen;
  double loopcycles;
  vector<ZZ> encryptedmsg;
  string decryptedmessage = "";
};
