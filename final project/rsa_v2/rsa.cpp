/*  Programmer:     Kyle Landrith
    Date Competed:  11/27/19
    Resources:      https://brilliant.org/wiki/rsa-encryption/
                    https://simple.wikipedia.org/wiki/RSA_algorithm
                    https://en.wikipedia.org/wiki/Modular_exponentiation#Pseudocode
                    https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
                    https://www.geeksforgeeks.org/measure-execution-time-function-cpp/
                    https://www.ttmath.org/
    Description:    A simple program to perform RSA encryption on a string message
                    entered through console input. Generates random keys each time
                    the program is ran (out of two sets of five 290 digit primes).
                    Key length is 1954-1958 bits.
                    May possibly adapt it in the future to work
                    with file input and file output.
                    This project uses the Bignum library for handling large integer values
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

    cout << "\nRandom prime numbers have been selected for use in\n"
         << "generating the public and private keys. \np: " << rsa.getP()
         << "\nq: " << rsa.getQ() <<"\n"
         << "An small random odd integer that is coprime to\n"
         << "(p - 1) * (q - 1) has been selected for the value of e.\n"
         << "Key length is approximately 1954-1958 bits.\n"
         << "\nPublic key is: \nn:\n" << rsa.getN() << "\ne:\n" << rsa.getE()
         << "\n"
         << "\nPrivate key is: \nn:\n" << rsa.getN() << "\nd:\n" << rsa.getD()
         << "\n";

    cout << "\nEncrypted messaged is:\n" << rsa.getEncrypted() << endl;
    cout << "\nDecrypting message..." << endl;
    auto startDecrypt = high_resolution_clock::now();
    rsa.decrypt();
    auto stopDecrypt = high_resolution_clock::now();
    auto durationDecrypt = duration_cast<microseconds>(stopDecrypt - startDecrypt);
    cout << "\nMessage took " << durationEncrypt.count() << "ms to encrypt...\n"
         << "\nMessage took " << durationDecrypt.count() << "ms to decrypt...\n"
         << "\nDecrypted message is: \n" << rsa.getDecrypted() << endl;
    cout << "\n\nEnter 0 to exit, 1 to encrypt another message: ";
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
