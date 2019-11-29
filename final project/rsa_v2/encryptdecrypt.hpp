
/*  Programmer:     Kyle Landrith
    Date Competed:  11/27/19
    Resources:      https://brilliant.org/wiki/rsa-encryption/
                    https://simple.wikipedia.org/wiki/RSA_algorithm
                    https://en.wikipedia.org/wiki/Modular_exponentiation#Pseudocode
                    https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
    Description:    A class implementation and declaration to implement simple RSA
                    encryption.
                    [note: prime numbers are originally stored in a string array
                    because the ttmath library will not allow initializing integers
                    to that large of a number, however it will support it, so it has
                    to be assigned as a string and then converted]
*/

#pragma once

#include <ctime>
#include <string>
#include <sstream>
#include <iostream>
#include <cassert>
#include "ttmath/ttmath.h"

using std::rand;
using std::string;
using std::stringstream;
using std::stoi;

class RSA {
public:
  // constructor
  RSA(unsigned int msgsize) {
    // initialize dynamic arrays and set msglength for array sizes
    msglength = msgsize;
    msg = new ttmath::Int<64>[msglength];
    encryptedmsg = new ttmath::Int<64>[msglength];
    decryptedmsg = new char[msglength];
    // convert from strings to nummbers for prime numbers
    // ttmath library does not support direct assignment
    // of that large of a number without assigning it from a string
    // for some unknown reason...
    for (int i = 0; i < 10; i++) {
      primenumbers1[i].FromString(prime1string[i], 10);
    }
    for (int i = 0; i < 5; i++) {
      primenumbers2[i].FromString(prime2string[i], 10);
    }
  }

  // destructor
  ~RSA() {
    delete []msg;
    delete []encryptedmsg;
    delete []decryptedmsg;
  }

  // encryption function
  void encrypt(string message) {
    int index1, index2, eindex;
    // Seed the Random Number Generator
    srand(time(0));
    index1 = rand() % 10;
    index2 = rand() % 5;
    p = primenumbers1[index1];
    q = primenumbers2[index2];
    n = p * q;
    phi = (p - 1) * (q - 1);
    // test if e and phi are coprime, if not change value of e until they are
    while (true) {
      e = makeE();
      if (gcd(e, phi) == 1) break;
    }
    d = modInverse(e, phi);
    // convert the message from a string into an interger array
    // with type coercion
    for (int i = 0; i < msglength; i++) {
      msg[i] = message.at(i);
    }
    // encrypt the message and store it as an integer array
    for (int i = 0; i < msglength; i++) {
      encryptedmsg[i] = modPow(msg[i], e, n);
    }
  }

  // decryption function
  void decrypt() {
    for (int i = 0; i < msglength; i++) {
      string str;
      stringstream stream;
      stream << modPow(encryptedmsg[i], d, n);
      str = stream.str();
      //testing code
      try {
        decryptedmsg[i] = stoi(str);
      } catch (const std::exception &e) {
        std::cout << e.what() << std::endl;
        std::cout << "current value of string stream to be stoi'd is: " << stream.str() << std::endl;
      }

      stream.ignore(str.size());
    }
  }

  // function to return a string representing encrytped message
  string getEncrypted() {
    stringstream stream;
    string str;
    for (int i = 0; i < msglength; i++) {
      stream << encryptedmsg[i];
      str += encryptedmsg[i].ToString(16);
    }
    return str;
  }

  // function to return a string representing decrypted message
  string getDecrypted() {
    stringstream stream;
    for (int i = 0; i < msglength; i++) {
      stream << decryptedmsg[i];
    }
    return stream.str();
  }

  // functions to return a string version of variables and keys
  string getP() {
    stringstream stream;
    stream << p;
    return stream.str();
  }

  string getQ() {
    stringstream stream;
    stream << q;
    return stream.str();
  }

  string getN() {
    stringstream stream;
    stream << n;
    return stream.str();
  }

  string getE() {
    stringstream stream;
    stream << e;
    return stream.str();
  }

  string getD() {
    stringstream stream;
    stream << d;
    return stream.str();
  }

private:
    // function to perform modular exponentiation to solve base^exp % mod
    // modular exponentiation splits the exponents into component parts,
    // ex: 2^90 = 2^50 * 2^40 so that we avoid overrunning the register size when calculating
    // even moderately large exponents such as is done when performing RSA encryption prior
    // to calling modulus on them for encryption/decryption, as well as to decrease overall
    // computation time. Without this, only small prime values may be used to generate the keys.
    // This implementation is called the right to left binary method and is based on
    // pseudocode from Applied Cryptograpgy by Bruce Schneier
    // computes in O(exponent) time
    ttmath::Int<64> modPow(ttmath::Int<64> base, ttmath::Int<64> exp, ttmath::Int<64> mod) {
      if (mod == 1) return 0;
      ttmath::Int<64> test1 = (mod - 1);
      ttmath::Int<64> test2 = (mod - 1);
      assert(!test1.Mul(test2));
      ttmath::Int<64> result = 1;
      base = base % mod;
      while (exp > 0) {
        if (exp % 2 == 1) result = (result * base) % mod;
        exp = exp >> 1;
        base = (base * base) % mod;
      }
      return result;
    }

    // function to find the modular multiplicative inverse d of e such that d*e = 1 mod phi
    // Iteratively uses the extended euclidean algorithm to
    // solve the following equation ax + by = gcd(a, b) for x
    // [note: assumes arguments passed are coprime]
    ttmath::Int<64> modInverse(ttmath::Int<64> e, ttmath::Int<64> phi) {
      ttmath::Int<64> phi0 = phi;
      ttmath::Int<64> y = 0, x = 1, quotient, temp;
      if (phi == 1) return 0;
      while (e > 1) {
        quotient = e / phi;
        temp = phi;
        // phi is remainder now, process same as
        // Euclid's algorithm
        phi = e % phi;
        e = temp;
        temp = y;
        // Update y and x
        y = x - quotient * y;
        x = temp;
      }
      // Make x positive
      if (x < 0) x += phi0;
      return x; // value of d for private key
    }

    // function to find the greatest common denominator of two integers
    // using euclides algorithm
    ttmath::Int<64> gcd(ttmath::Int<64> a, ttmath::Int<64> b) {
      if (b == 0) return a;
      return gcd(b, a % b);
    }

    // function to generate random e values
    unsigned int makeE() {
      // Seed the Random Number Generator
      srand(time(0));
      unsigned int e = rand() % 1001 + 7;
      return e;
    }

  // variables needed for encryption/decryption
  ttmath::Int<64> p, q, phi, n, e, d;
  int msglength;
  ttmath::Int<64> primenumbers1[5];
  ttmath::Int<64> primenumbers2[5];
  string prime1string[10] = {"28911710017320205966167820725313234361535259163045867986277478145081076845846493521348693253530011243988160148063424837895971948244167867236923919506962312185829914482993478947657472351461336729641485069323635424692930278888923450060546465883490944265147851036817433970984747733020522259537",
                            "16471581891701794764704009719057349996270239948993452268812975037240586099924712715366967486587417803753916334331355573776945238871512026832810626226164346328807407669366029926221415383560814338828449642265377822759768011406757061063524768140567867350208554439342320410551341675119078050953",
                            "66906174941351898982237115390104837800016519944803542107267307151873963667405652882882234979074916465840726363291254831297728195876839948476821111362547660187546080833118811138386335112324867302804187267930262901208266565865718143732715527778968965624024419434824986425142476236837724711619",
                            "17160441645030935264127918488197223044423032294949290607725329385702867211094124452026640439869290520138575924093242319478564624951322485066038129421782264744932574479313896348123684939555661072794352801320851822124548964799270331635834170197712511573673852876021092210734677851423038145589",
                            "41881970328229837575862121024586873839118624339720906926151959380017384630908360261281114858896239995979802524451414999099221056661311384631724751694216776973306953252147904807235529083826421541134486578078657958631274409702333847706219977904901768889130257692466383613649686862454370409751",
                            "12574310210568992295391236743812326726776482174353588657900645266285757770843033428320489364472989127456336702810628971254254492560827343895265298738632502255009593271051579723815454872757538904746185448795343318827589544795905106549913395621470148459136748084837312416788281030641376776461",
                            "47636001527157843615510166362212813825553995166349359052560828063795751982743949356281378571281356684995526346349689115319412565735006540850254022130876377867983398374239198108049044484863543699346022227692817853215225730056764957039852693911896900286014520659611654434776741074401112976951",
                            "36997438997453671132166865292569847244619444010395996997269402633033171733524207782461697123413414988859119764706460324782855919613943534861045216286685374559389860714010358938897470990143322775796082401132386180536650715835089633575578638914905606853502795766373129779823319637155282395679",
                            "33224988939958325005500695671267617338874622885890390533881719663053642478645240639084719290104519985775137683284635121762491364078202654759655915865377054667244894109025593792728931763489582862581707296760107534128977579042328333430944033239749124630128178571199381307853292264015434330633",
                            "66411949393245949268811711602826765576402057646975003006251042260813215340087318062380031915073315092183806206493533345953281647263552710655695269967337089850144857674638489475995919778552032603791816048265084649175429768094838031170157033168866305251844356097795408000548418783227194651709"};
  string prime2string[5] = {"203956878356401977405765866929034577280193993314348263094772646453283062722701277632936616063144088173312372882677123879538709400158306567338328279154499698366071906766440037074217117805690872792848149112022286332144876183376326512083574821647933992961249917319836219304274280243803104015000563790123",
                            "531872289054204184185084734375133399408303613982130856645299464930952178606045848877129147820387996428175564228204785846141207532462936339834139412401975338705794646595487324365194792822189473092273993580587964571659678084484152603881094176995594813302284232006001752128168901293560051833646881436219",
                            "319705304701141539155720137200974664666792526059405792539680974929469783512821793995613718943171723765238853752439032835985158829038528214925658918372196742089464683960239919950882355844766055365179937610326127675178857306260955550407044463370239890187189750909036833976197804646589380690779463976173",
                            "250556952327646214427246777488032351712139094643988394726193347352092526616305469220133287929222242315761834129196430398011844978805263868522770723615504744438638381670321613949280530254014602887707960375752016807510602846590492724216092721283154099469988532068424757856392563537802339735359978831013",
                            "290245329165570025116016487217740287508837913295571609463914348778319654489118435855243301969001872061575755804802874062021927719647357060447135321577028929269578574760547268310055056867386875959045119093967972205124270441648450825188877095173754196346551952542599226295413057787340278528252358809329"};
  ttmath::Int<64> *msg;
  ttmath::Int<64> *encryptedmsg;
  char *decryptedmsg;
};
