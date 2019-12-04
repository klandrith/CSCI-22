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
#include <fstream>
#include <string>
#include <chrono>
#include "encryptdecrypt.hpp"
#include "CinReader.h"

using std::cout;
using std::endl;
using std::string;
using std::getline;
using namespace std::chrono;

void ClearScreen();
void EnterContinue(string message);

int main() {
  // create instance of cinreader for input as wekk as isntance of RSA class
  string message;
  CinReader reader;
  RSA rsa;


  ClearScreen();
  cout << "****************************************************************\n"
       << "*                                                              *\n"
       << "*              ~~~RSA Algorithm Implementation~~~              *\n"
       << "*                                                              *\n"
       << "*                          Author: Kyle Landrith               *\n"
       << "*                                                              *\n"
       << "****************************************************************\n";

  cout << "\n\nEnter 1 if you would like to encrypt a text file, or 2 to\n"
       << "decrypt one: ";
  unsigned int selection = reader.readInt(1,2);
  

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
