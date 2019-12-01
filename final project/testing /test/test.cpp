#include <iostream>
#include <string>
#include <sstream>
#include <NTL/ZZ.h>
#include <ctime>
#include <cstring>

using std::string;
using std::stringstream;
using std::stoi;
using namespace NTL;
using std::cin;
using std::cout;
using std::endl;

template <typename T>
int countBits(T value);

int main() {
  ZZ n;
  long primelength;
  primelength = 256;
  long error;
  error = 80;
  ZZ p;
  ZZ q;
  // generate 1024 bit primes that are different
  cout << "Generating primes..." << endl;
  while (p == q) {
    p = GenGermainPrime_ZZ(primelength, error);
    q = GenGermainPrime_ZZ(primelength, error);
  }
  n = p * q;
  ZZ phi = (p - 1) * (q - 1);
  ZZ e;
  ZZ d;
  ZZ seed;
  seed = 555;
  void SetSeed(const ZZ& seed);
  // set bit length for e generation
  long elength;
  elength = 64;
  // test if e and phi are coprime, if not change value of e until they are
  while (true) {
    e = RandomLen_ZZ(elength);
    if (GCD(e, phi) == 1 && e > 7) break;
  }
  d = InvMod(e, phi);
  char message;
  cout << "Enter a single character to encrypt: ";
  cin >> message;
  unsigned int asciiValue = message;
  unsigned int keyLen = (countBits(n) + 7) / 8;
  unsigned int psLen = keyLen - (countBits(asciiValue) / 8) - 3;
  unsigned char eblock[keyLen];
  eblock[0] = 0x00;
  eblock[1] = 0x02;
  srand(time(0));
  // fill PS
  for (int i = 2; i < 2+keyLen; i++) {
    eblock[i] = rand() % i + 1;
  }
  eblock[2 + psLen] = 0x00;
  eblock[3+psLen] = asciiValue;
  stringstream stream;
  for (int i = 0; i <= keyLen; i++) {
    unsigned int temp = eblock[i];
    stream << temp;
  }
  ZZ temp;
  stream >> temp;
  cout << "Encrypting..." << endl;
  ZZ encrypted = PowerMod(temp, e, n);
  cout << "\n" << "Encrypted message:\n"
       << encrypted << endl;

  /*
  unsigned int padLen = keyLen - (countBits(encrypted) / 8);

  for (int i = 0; i < padLen; i++) {
    eblock[i] = 0x00;
  }

  unsigned char *ptr1 = new unsigned char[keyLen];
  ptr1 = eblock;
  ZZ *ptr2 = new ZZ;
  ptr2 = &encrypted;
  memcpy(ptr1, ptr2, sizeof(encrypted));

  stream.ignore(stream.str().size());
  for (int i = 0; i <= keyLen; i++) {
    stream << eblock[i];
  }
  string tempstr = stream.str();
  cout << "after looping, emsg: \n" << tempstr << endl;
  */



  cout << "\n\nDecrypyting..." << endl;
  ZZ decrypted = PowerMod(encrypted, d, n);
  // clear stream for next round of for loop
  stream.ignore(stream.str().size());
  stream << decrypted;
  string tempString = stream.str();
  cout << "\nDecrypted raw:\n" << tempString << endl;
  string decryptedMsg = tempString.substr(tempString.size() - 3, string::npos);
  cout << "\nDecrypted message: " << decryptedMsg << endl;
  char dmsg = stoi(decryptedMsg);
  cout << "\n" << dmsg << endl;

  unsigned char tempchar;
  tempchar = 0x00;
  unsigned int tempint = tempchar;
  cout << "\n0x00 is: " << tempint << endl;





  return 0;
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
