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
    testmessage = "", outputmessage = "";
    char alphabet[52] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g',
                          'h', 'i', 'j', 'k', 'l', 'm', 'n',
                          'o', 'p', 'q', 'r', 's', 't', 'u',
                          'v', 'w', 'x', 'y', 'z', 'A', 'B',
                          'C', 'D', 'E', 'F', 'G', 'H', 'I',
                          'J', 'K', 'L', 'M', 'N', 'O', 'P',
                          'Q', 'R', 'S', 'T', 'U', 'V', 'W',
                          'X', 'Y', 'Z'};

    //unsigned int numchars = rand() % 10000 + 9999;
    unsigned int numchars = rand() % 20 + 1;
    for (int i = 0; i < numchars; i++) {
      unsigned int index = rand() % 52;
      testmessage = testmessage += alphabet[index];
    }
    rsa.generateKeys();
    auto startEncrypt = high_resolution_clock::now();
    rsa.EncryptRSA(testmessage);
    auto stopEncrypt = high_resolution_clock::now();
    auto durationEncrypt = duration_cast<milliseconds>(stopEncrypt - startEncrypt);
    auto startDecrypt = high_resolution_clock::now();
    rsa.DecryptRSA();
    auto stopDecrypt = high_resolution_clock::now();
    auto durationDecrypt = duration_cast<milliseconds>(stopDecrypt - startDecrypt);
    inputmessage = testmessage;
    outputmessage = rsa.getDecrypted();

    cout << "\nMessage took " << durationEncrypt.count() << "ms to encrypt...\n";
    cout << "Message took " << durationDecrypt.count() << "ms to decrypt...\n";

    cout << "\n" << testmessage << endl;
    cout << "\n\n" << outputmessage << endl;
    if (testmessage != outputmessage) break;
    cout << "Continuing testing values for encryption..." << endl;
  }
  cout << "ERROR! ENCRYPTION/DECRYPTION FAILED!!!" << endl;


 return 0;
}
