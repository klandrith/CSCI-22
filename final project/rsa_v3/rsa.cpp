/*  Programmer:     Kyle Landrith
    Date Competed:  11/27/19
    Resources:      https://brilliant.org/wiki/rsa-encryption/
                    https://simple.wikipedia.org/wiki/RSA_algorithm
                    https://en.wikipedia.org/wiki/Modular_exponentiation#Pseudocode
                    https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
                    https://www.geeksforgeeks.org/measure-execution-time-function-cpp/
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
#include <unistd.h>
#include <chrono>
#include "CinReader.h"
#include "encryptdecrypt.hpp"

using std::cin;
using std::cout;
using std::string;
using std::getline;
using namespace std::chrono;

void ClearScreen();

int main() {
  int selection = 0;
  string message;
  CinReader reader;

  do {
    ClearScreen();
    cout  << "Enter the message to encrypt:\n";
    getline(cin, message);
    RSA rsa(message.size());

    auto startEncrypt = high_resolution_clock::now();
    rsa.encrypt(message);
    auto stopEncrypt = high_resolution_clock::now();
    auto durationEncrypt = duration_cast<microseconds>(stopEncrypt - startEncrypt);

    cout << "\nEncrypted messaged is:\n" << rsa.getEncrypted() << endl;

    auto startDecrypt = high_resolution_clock::now();
    rsa.decrypt();
    auto stopDecrypt = high_resolution_clock::now();
    auto durationDecrypt = duration_cast<microseconds>(stopDecrypt - startDecrypt);

    cout << "\nRandom prime numbers have been selected for use in\n"
         << "generating the public and private keys. \n\np: " << rsa.getP()
         << "\n\nq: " << rsa.getQ() <<"\n"
         << "\nA random odd integer that is coprime to (p - 1) * (q - 1)\n"
         << "has been selected for the value of e.\n"
         << "Key length is " << rsa.countBits() << " bits.\n"
         << "\nPublic key is: \nn:\n" << rsa.getN() << "\ne:\n" << rsa.getE()
         << "\n"
         << "\nPrivate key is: \nn:\n" << rsa.getN() << "\nd:\n" << rsa.getD()
         << "\n"
         << "\nMessage took " << durationEncrypt.count() << "ms to encrypt...\n"
         << "\nMessage took " << durationDecrypt.count() << "ms to decrypt...\n"
         << "\nDecrypted message is: \n" << rsa.getDecrypted() << endl
         << "\n\nEnter 0 to exit, 1 to encrypt another message: ";

    selection = reader.readInt(0, 1);
  } while(selection == 1);
  ClearScreen();

 return 0;
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
