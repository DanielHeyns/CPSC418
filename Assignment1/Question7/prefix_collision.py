#!/usr/bin/env python3

import argparse

import string
import random
import time
from cryptography.hazmat.primitives import hashes

# Insert your imports from the cryptography module here

def string_to_bytes( string ):
   """A helper function to convert strings into byte objects.

   PARAMETERS
   ==========
   input: A string to be converted to bytes.

   RETURNS
   =======
   A bytes version of the string.
   """

   return string.encode('utf-8')


def hash_bytes( input ):
   """Hash the given input using SHA-2 224.

   PARAMETERS
   ==========
   input: A bytes object containing the value to be hashed.

   RETURNS
   =======
   A bytes object containing the hash value.
   """
   myhash = hashes.Hash(hashes.SHA224())
   myhash.update(input)
   hashed_output = myhash.finalize()
   return hashed_output



def compare_bytes( A, B, length ):
   """Compare the first 'length' bytes of A and B to see if they're identical.

   PARAMETERS
   ==========
   A: A bytes object containing one value to be compared.
   B: A bytes object containing the other value to be compared.
   length: An integer representing the number of bytes to be compared.

   RETURNS
   =======
   If the first 'length' bytes of A and B match, return True. For all other cases,
     such as one of the bytes object being shorter than 'length', return False.
   """
   # print("Comparing " + A[:length].hex() + " and " + B[:length].hex())
   return A[:length] == B[:length]


def find_collision( length ):
   """Find a SHA2 224 collision, where the first 'length' bytes of the hash tag match but
      the two byte objects are different.

   PARAMETERS
   ==========
   length: An integer representing the number of bytes to be compared.

   RETURNS
   =======
   A tuple of the form (A, B), where A and B are two byte objects with a suitable SHA2 224
    collision and A != B. If you can't find a collision, return None instead. Do not return
    the hashes of A and/or B!
   """
   lett = string.ascii_letters
   myHashes = {}
   while(1):
    password = ''.join(random.choices(lett, k=10))
    hashedPassT = hash_bytes(string_to_bytes(password))[:length]
    if(hashedPassT in myHashes):
        return (string_to_bytes(password), string_to_bytes(myHashes[hashedPassT]))
    myHashes[hashedPassT] = password

   

if __name__ == '__main__':

   cmdline = argparse.ArgumentParser(description='Find two hash collisions, within the given length.')
   cmdline.add_argument( '--length', metavar='INT', type=int, default=2, help='The first X characters of the hashes that must match.' )

   args = cmdline.parse_args()

   if args.length < 1:
      print( f"ERROR! Please supply a length that's greater than 0, not '{args.length}'." )


   ret = find_collision( args.length )
   if ret is None:
      print( f"I'm sorry, I couldn't find a collision for length {args.length}. Please try a shorter value." )
   elif (type(ret) is tuple) and (len(ret) == 2):
      print( f"I found a collision where the first {args.length} of the hash match!" )
      A, B = ret
      print( f"{hash_bytes(A).hex()} = HASH({A})" ) 
      print( f"{hash_bytes(B).hex()} = HASH({B})" )
