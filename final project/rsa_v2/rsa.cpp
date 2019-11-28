/*  Programmer:     Kyle Landrith
    Date Competed:  11/27/19
    Resources:      https://brilliant.org/wiki/rsa-encryption/
                    https://simple.wikipedia.org/wiki/RSA_algorithm
                    https://don.p4ge.me/modular-exponentiation/programming
                    https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
    Description:    A simple program to perform RSA encryption on a string message
                    entered through console input. Generates random keys each time
                    the program is ran (out of two sets of five 290 digit primes).
                    Key length is approximately 1954 bits.
                    May possibly adapt it in the future to work
                    with file input and file output.
*/
#include <iostream>
#include <string>
#include <unistd.h>
#include "CinReader.h"
#include "encryptdecrypt.hpp"

using std::cin;
using std::cout;
using std::string;
using std::getline;

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
    rsa.encrypt(message);

    cout << "\nRandom prime numbers have been selected for use in\n"
         << "generating the public and private keys. \np: " << rsa.getP()
         << "\nq: " << rsa.getQ() <<"\n"
         << "An odd number between 9 and 47 that is coprime to\n"
         << "(p - 1) * (q - 1) has been selected for the value of e.\n"
         << "Key length is approximately 1954 bits.\n"
         << "\nPublic key is: \nn:\n" << rsa.getN() << "\ne:\n" << rsa.getE()
         << "\n"
         << "\nPrivate key is: \nn:\n" << rsa.getN() << "\nd:\n" << rsa.getD()
         << "\n";

    cout << "\nEncrypted messaged is:\n" << rsa.getEncrypted() << endl;
    cout << "\nDecrypting message..." << endl;
    rsa.decrypt();
    cout << "\nDecrypted message is: \n" << rsa.getDecrypted() << endl;
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
