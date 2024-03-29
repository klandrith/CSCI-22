/*  Programmer:     Kyle Landrith
    Date Competed:  12/4/19
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
#include "CinReader.h"
#include "encryptdecrypt.hpp"

using std::cout;
using std::endl;
using std::string;
using std::getline;
using namespace std::chrono;

void ClearScreen();
void EnterContinue(string message);

int main() {
  // create instance of cinreader for input as wekk as isntance of RSA class
  int selection = 0;
  string message;
  CinReader reader;
  RSA rsa;

  // menu loop
  do {
    ClearScreen();
    cout << "****************************************************************\n"
         << "*                                                              *\n"
         << "*              ~~~RSA Algorithm Implementation~~~              *\n"
         << "*                                                              *\n"
         << "*                          Author: Kyle Landrith               *\n"
         << "*                                                              *\n"
         << "****************************************************************\n";



    cout << "\n\n\nEnter the message to encrypt and press enter:\n";
    getline(cin, message);
    EnterContinue("\nPress enter to generate keys...");
    auto startKey = high_resolution_clock::now();
    rsa.generateKeys();
    auto stopKey = high_resolution_clock::now();
    auto durationKey = duration_cast<microseconds>(stopKey - startKey);

    cout << "\nRandom prime numbers have been selected for use in\n"
         << "generating the public and private keys. \n\np: " << rsa.getP();
    cout << "\n\nq: " << rsa.getQ() <<"\n"
         << "\nThe value of 65537 has been selected for e. Primes have been\n"
         << "calculated such that GCD(e, (p - 1) * (q - 1)) == 1.\n"
         << "\nKey length is " << rsa.keyLength() << " bits.\n";
    cout << "\nKeys took " << durationKey.count() << " microseconds to generate...\n";
    EnterContinue("Press enter to display the public key...");
    cout << "\nPublic key is: \n\nn: " << rsa.getN() << "\n\ne: " << rsa.getE()
         << "\n";
    EnterContinue("Press enter to display the private key...");
    cout << "\nPrivate key is: \n\nn: " << rsa.getN() << "\n\nd: " << rsa.getD() << endl;

    EnterContinue("Press enter to begin encryption...");
    auto startEncrypt = high_resolution_clock::now();
    rsa.EncryptRSA(message);
    auto stopEncrypt = high_resolution_clock::now();
    auto durationEncrypt = duration_cast<microseconds>(stopEncrypt - startEncrypt);
    cout << "\nMessage took " << durationEncrypt.count() << " microseconds to encrypt...\n";

    EnterContinue("Press enter to display encrypted message...");
    cout << "\nEncrypted messaged is:\n" << rsa.getEncrypted() << endl;
    EnterContinue("Press enter to begin decryption...");

    auto startDecrypt = high_resolution_clock::now();
    rsa.DecryptRSA();
    auto stopDecrypt = high_resolution_clock::now();
    auto durationDecrypt = duration_cast<microseconds>(stopDecrypt - startDecrypt);

    cout << "Message took " << durationDecrypt.count() << " microseconds to decrypt...\n";
    EnterContinue("Press enter to display decrypted message...");
    cout << "\nDecrypted message is: \n" << rsa.getDecrypted() << endl
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

// function Continue displays a message prompts user to press any key to continue
void EnterContinue(string message) {
  CinReader reader;
  string enter_accept;
  cout << endl;
  cout << message;
  enter_accept = reader.readString();
  ClearScreen();
}
