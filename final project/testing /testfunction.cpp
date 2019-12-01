/*  Programmer:     Kyle Landrith
    Date Competed:  11/29/19
    Resources:      https://brilliant.org/wiki/rsa-encryption/
                    https://simple.wikipedia.org/wiki/RSA_algorithm
                    https://www.shoup.net/ntl/
                    https://www.geeksforgeeks.org/measure-execution-time-function-cpp/
                    https://www.includehelp.com/cpp-programs/find-total-number-of-bits-required-to-represent-a-number-in-binary.aspx
                    https://eli.thegreenplace.net/2019/rsa-theory-and-implementation/
    Description:    A simple program to perform RSA encryption on a string message
                    entered through console input (ASCII characters only).
                    Generates random keys each time the program is ran.
                    Key length is ~2048 bits.
                    May possibly adapt it in the future to work
                    with file input and file output, as well as padding.
                    [note:] This project uses the NTL library for handling large
                    integer values and to perform various arithmetic operations
                    necessary for the RSA encryption/decryption algorithm.
*/
#include <iostream>
#include <string>
#include <chrono>
#include "encryptdecrypt.hpp"

using std::cin;
using std::cout;
using std::endl;
using std::string;
using std::getline;
using namespace std::chrono;

int main() {
  RSA rsa;
  string testmessage;
  // seed pseudo random number generators
  srand(time(0));
  while (true) {
    string inputmessage, outputmessage;
    testmessage = "";
    char alphabet[52] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g',
                          'h', 'i', 'j', 'k', 'l', 'm', 'n',
                          'o', 'p', 'q', 'r', 's', 't', 'u',
                          'v', 'w', 'x', 'y', 'z', 'A', 'B',
                          'C', 'D', 'E', 'F', 'G', 'H', 'I',
                          'J', 'K', 'L', 'M', 'N', 'O', 'P',
                          'Q', 'R', 'S', 'T', 'U', 'V', 'W',
                          'X', 'Y', 'Z'};

    for (int i = 0; i < 10000; i++) {
      ZZ randnumber = RandomLen_ZZ(51);
      unsigned int index;
      conv(index, randnumber);
      testmessage = testmessage + alphabet[rand() % 52];
    }
    rsa.generateKeys(1024);
    rsa.EncryptRSA(testmessage);
    rsa.DecryptRSA();
    inputmessage = testmessage;
    outputmessage = rsa.getDecrypted();

    if (testmessage != outputmessage) break;
    cout << testmessage << endl;
    cout << "Continuing testing values for encryption..." << endl;
  }
  cout << "ERROR! ENCRYPTION/DECRYPTION FAILED!!!" << endl;


 return 0;
}
