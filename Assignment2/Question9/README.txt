Generating Prime N: 
I generate a random 63 byte number and add 2^510 to it to ensure i get the right number of bits. I then check if this number is prime and if 2*thegeneratednumber + 1 is prime. If both of these are true then i return 2 * thegeneratednumber +1.

Generating the primitive root g of N:
The two primefactors of N-1 are 2 and N/2 as the formula used to generate N 2 * q +1. I use the formula  i^N-1/primefactorx mod N and check if it is not equal to 1 for both primefactors of N-1, if it is then I return i.

List of files
basic_auth.py : Implements a password-based key agreement protocol between a client and server. A client and server can be run from the program via different commands and are able to connect to one another and generate a shared Key over an insecure channel.

Everything is implemented

No known bugs, although the autograder doesnt work. I tested the program on a linux machine with reduced a, b and u values to reduce runtime and I encountered no errors.