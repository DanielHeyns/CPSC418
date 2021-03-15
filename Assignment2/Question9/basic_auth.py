#!/usr/bin/env python3
#Daniel Heyns (30021292)
#basic_auth.py
##### IMPORTS

import argparse
from multiprocessing import Process
from sys import exit
from time import sleep

# Insert your imports here
import socket
import os
import math
from sympy.ntheory import isprime
from cryptography.hazmat.primitives import hashes
import sys
##### METHODS

def split_ip_port( string ):
    """Split the given string into an IP address and port number.
    
    PARAMETERS
    ==========
    string: A string of the form IP:PORT.

    RETURNS
    =======
    If successful, a tuple of the form (IP,PORT), where IP is a 
      string and PORT is a number. Otherwise, returns None.
    """

    assert type(string) == str

    try:
        idx = string.index(':')
        return (string[:idx], int(string[idx+1:]))
    except:
        return None

def int_to_bytes( value, length ):
    """Convert the given integer into a bytes object with the specified
       number of bits. Uses network byte order.

    PARAMETERS
    ==========
    value: An int to be converted.
    length: The number of bytes this number occupies.

    RETURNS
    =======
    A bytes object representing the integer.
    """
    
    assert type(value) == int
    assert length > 0

    return value.to_bytes( length, 'big' )

def bytes_to_int( value ):
    """Convert the given bytes object into an integer. Uses network
       byte order.

    PARAMETERS
    ==========
    value: An bytes object to be converted.

    RETURNS
    =======
    An integer representing the bytes object.
    """
    if type(value) == bytearray:
        value = bytes(value)
    assert type(value) == bytes
    return int.from_bytes( value, 'big' )

#Added Helper Functions

def hash_bytes( input ):
   """Hash the given input using SHA-2 224.

   PARAMETERS
   ==========
   input: A bytes object containing the value to be hashed.

   RETURNS
   =======
   A bytes object containing the hash value.
   """
   myhash = hashes.Hash(hashes.SHA256())
   myhash.update(input)
   hashed_output = myhash.finalize()
   return hashed_output


def create_socket( ip, port, listen=False ):
    """Create a TCP/IP socket at the specified port, and do the setup
       necessary to turn it into a connecting or receiving socket. Do
       not actually send or receive data here!

    PARAMETERS
    ==========
    ip: A string representing the IP address to connect/bind to.
    port: An integer representing the port to connect/bind to.
    listen: A boolean that flags whether or not to set the socket up
       for connecting or receiving.

    RETURNS
    =======
    If successful, a socket object that's been prepared according to 
       the instructions. Otherwise, return None.
    """
    
    assert type(ip) == str
    assert type(port) == int
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if(listen):
            s.bind((ip,port))
            s.listen()
            print("Server Listening...")
            return s
        else:
            print("Client Connecting...")
            s.connect((ip,port))
            print("Client Connected!")
            return s
    except:
        print("Exception in Socket Creation") 
        return None

def send( sock, data ):
    """Send the provided data across the given socket. This is a
       'reliable' send, in the sense that the function retries sending
       until either a) all data has been sent, or b) the socket 
       closes.

    PARAMETERS
    ==========
    sock: A socket object to use for sending and receiving.
    data: A bytes object containing the data to send.

    RETURNS
    =======
    The number of bytes sent. If this value is less than len(data),
       the socket is dead and a new one must be created, plus an unknown
       amount of the data was transmitted.
    """
    
    assert type(sock) == socket.socket
    assert type(data) == bytes
    try:
        bytesSent = sock.send(data)
    except:
        print("Exception in Socket Send") 
    return bytesSent


def receive( sock, length ):
    """Receive the provided data across the given socket. This is a
       'reliable' receive, in the sense that the function never returns
       until either a) the specified number of bytes was received, or b) 
       the socket closes. Never returning is an option.

    PARAMETERS
    ==========
    sock: A socket object to use for sending and receiving.
    length: A positive integer representing the number of bytes to receive.

    RETURNS
    =======
    A bytes object containing the received data. If this value is less than 
       length, the socket is dead and a new one must be created.
    """
    
    assert type(sock) == socket.socket
    assert length > 0
    try:
        data = bytearray()
        while True:
            receivedData = sock.recv(length-len(data))
            if not receivedData:
                return None
            data += receivedData
            if len(data) >= length:
                print("break on length")
                break
    except:
        print("Exception in Socket Recieve") 
    return data

def safe_prime( bits=512 ):
    """Generate a safe prime that is at least 'bits' bits long. The result
       should be greater than 1 << (bits-1).

    PARAMETERS
    ==========
    bits: An integer representing the number of bits in the safe prime.
       Must be greater than 1.

    RETURNS
    =======
    An interger matching the spec.
    """

    assert bits > 1
    if bits < 8: bits = 8
    serial = int.from_bytes(os.urandom(int((bits-1)/8)), byteorder="big") + pow(2, bits-2)
    while not (isprime(serial) and isprime (2 * serial + 1)):
        serial = int.from_bytes(os.urandom(int((bits-1)/8)), byteorder="big") + pow(2, bits-2)
    return 2 * serial + 1

def prim_root( N ):
    """Find a primitive root for N, a large safe prime. Hint: it isn't
       always 2.

    PARAMETERS
    ==========
    N: The prime in question. May be an integer or bytes object.

    RETURNS
    =======
    An integer representing the primitive root. Must be a positive
       number greater than 1.
    """
    X = N - 1 
    primeFactor1 = 2
    primeFactor2 = X/2
    for i in range(2,X):
        if pow(i,int(X/primeFactor1),N) != 1 and pow(i,int(X/primeFactor2),N) != 1:
            return i
    return None


def calc_x( s, pw ):
    """Calculate the value of x, according to the assignment.

    PARAMETERS
    ==========
    s: The salt to use. A bytes object consisting of 16 bytes.
    pw: The password to use, as a string.

    RETURNS
    =======
    An integer representing x.
    """

    assert type(pw) == str
    return bytes_to_int(hash_bytes(s + pw.encode('utf-8')))
    

def calc_A( N, g, a ):
    """Calculate the value of A, according to the assignment.

    PARAMETERS
    ==========
    N: The safe prime. Could be an integer or bytes object.
    g: A primitive root of N. Could be an integer or bytes object.
    a: A random value between 0 and N-1, inclusive. Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing A.
    """
    
    if type(N) in [bytes, bytearray]:
        N = bytes_to_int(N)
    if type(g) in [bytes, bytearray]:
        g = bytes_to_int(g)
    if type(a) in [bytes, bytearray]:
        a = bytes_to_int(a)
    return pow(g, a, N)

def calc_B( N, g, b, k, v ):
    """Calculate the value of B, according to the assignment.

    PARAMETERS
    ==========
    N: The safe prime. Could be an integer or bytes object.
    g: A primitive root of N. Could be an integer or bytes object.
    b: A random value between 0 and N-1, inclusive. Could be an integer or bytes object.
    k: The hash of N and g. Could be an integer or bytes object.
    v: See calc_v(). Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing B.
    """
    if type(N) in [bytes, bytearray]:
        N = bytes_to_int(N)
    if type(g) in [bytes, bytearray]:
        g = bytes_to_int(g)
    if type(b) in [bytes, bytearray]:
        b = bytes_to_int(b)
    if type(k) in [bytes, bytearray]:
        k = bytes_to_int(k)
    if type(v) in [bytes, bytearray]:
        v = bytes_to_int(v)

    return (k * v + pow(g,b)) % N

def calc_u( A, B ):
    """Calculate the value of u, according to the assignment.

    PARAMETERS
    ==========
    A: See calc_A(). Could be an integer or bytes object.
    B: See calc_B(). Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing u.
    """
    if type(A) == int:
        lengthA = A.bit_length()
        lengthA = int(math.ceil(lengthA/8))
        A = int_to_bytes(A,lengthA)
    if type(B) == int:
        lengthB = B.bit_length()
        lengthB = int(math.ceil(lengthB/8))
        B = int_to_bytes(B,lengthB)

    #CHANGED FOR TESTING FIX LATER
    #return bytes_to_int(hash_bytes(A+B))
    return 31
    

def calc_K_client( N, B, k, v, a, u, x ):
    """Calculate the value of K_client, according to the assignment.

    PARAMETERS
    ==========
    N: The safe prime. Could be an integer or bytes object.
    B: See calc_B(). Could be an integer or bytes object.
    k: The hash of N and g. Could be an integer or bytes object.
    v: See calc_v(). Could be an integer or bytes object.
    a: A random value between 0 and N-1, inclusive. Could be an integer or bytes object.
    u: The hash of A and B. Could be an integer or bytes object.
    x: See calc_x(). Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing K_client.
    """
    if type(N) in [bytes, bytearray]:
        N = bytes_to_int(N)
    if type(B) in [bytes, bytearray]:
        B = bytes_to_int(B)
    if type(k) in [bytes, bytearray]:
        k = bytes_to_int(k)
    if type(v) in [bytes, bytearray]:
        v = bytes_to_int(v)
    if type(a) in [bytes, bytearray]:
        a = bytes_to_int(a)
    if type(u) in [bytes, bytearray]:
        u = bytes_to_int(u)
    if type(x) in [bytes, bytearray]:
        x = bytes_to_int(x)
    
    return pow(B-k*v,a+u*x,N)



def calc_K_server( N, A, b, v, u ):
    """Calculate the value of K_server, according to the assignment.

    PARAMETERS
    ==========
    N: The safe prime. Could be an integer or bytes object.
    A: See calc_A(). Could be an integer or bytes object.
    b: A random value between 0 and N-1, inclusive. Could be an integer or bytes object.
    v: See calc_v(). Could be an integer or bytes object.
    u: The hash of A and B. Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing K_server.
    """
    if type(N) in [bytes, bytearray]:
        N = bytes_to_int(N)
    if type(A) in [bytes, bytearray]:
        A = bytes_to_int(A) 
    if type(b) in [bytes, bytearray]:
        b = bytes_to_int(b)
    if type(v) in [bytes, bytearray]:
        v = bytes_to_int(v)
    if type(u) in [bytes, bytearray]:
        u = bytes_to_int(u)
    print("calc_K")
    print(u)
    print(v)
    return pow(A*pow(v,u), b, N)

def calc_M1( A, B, K_client ):
    """Calculate the value of M1, according to the assignment.

    PARAMETERS
    ==========
    A: See calc_A(). Could be an integer or bytes object.
    B: See calc_B(). Could be an integer or bytes object.
    K_client: See calc_K_client(). Could be an integer or bytes object.

    RETURNS
    =======
    A bytes object representing M1.
    """

    if type(A) == int:
        lengthA = A.bit_length()
        lengthA = int(math.ceil(lengthA/8))
        A = int_to_bytes(A,lengthA)
    if type(B) == int:
        lengthB = B.bit_length()
        lengthB = int(math.ceil(lengthB/8))
        B = int_to_bytes(B,lengthB)
    if type(K_client) == int:
        lengthK = K_client.bit_length()
        lengthK = int(math.ceil(lengthK/8))
        K_client = int_to_bytes(K_client,lengthK)

    return hash_bytes(A + B + K_client)

def calc_M2( A, M1, K_server ):
    """Calculate the value of M2, according to the assignment.

    PARAMETERS
    ==========
    A: See calc_A(). Could be an integer or bytes object.
    M1: See calc_M1(). Could be an integer or bytes object.
    K_server: See calc_K_server(). Could be an integer or bytes object.

    RETURNS
    =======
    A bytes object representing M2.
    """

    if type(A) == int:
        lengthA = A.bit_length()
        lengthA = int(math.ceil(lengthA/8))
        A = int_to_bytes(A,lengthA)
    if type(M1) == int:
        lengthM1 = M1.bit_length()
        lengthM1 = int(math.ceil(lengthM1/8))
        M1 = int_to_bytes(M1,lengthM1)
    if type(K_server) == int:
        lengthK = K_server.bit_length()
        lengthK = int(math.ceil(lengthK/8))
        K_server = int_to_bytes(K_server,lengthK)

    return hash_bytes(A + M1 + K_server)

def client_prepare():
    """Do the preparations necessary to connect to the server. Basically,
       just generate a salt.

    RETURNS
    =======
    A bytes object containing a randomly-generated salt, 16 bytes long.
    """

    return os.urandom(16)

def server_prepare():
    """Do the preparations necessary to accept clients. Generate N and g,
       and compute k.

    RETURNS
    =======
    A tuple of the form (N, g, k), containing those values as integers.
    """

    N = safe_prime()
    lengthN = 64
    # lengthN = N.bit_length()
    # lengthN = int(math.ceil(lengthN/8))
    byteN = int_to_bytes(N, lengthN)

    g = prim_root(N)
    lengthG = 64
    # lengthG = g.bit_length()
    # lengthG = int(math.ceil(lengthG/8))
    byteG = int_to_bytes(g, lengthG)
    
    byteK = hash_bytes(byteN + byteG)
    k = int.from_bytes(byteK, "big")
    return (N, g, k)


def client_register( ip, port, username, pw, s ):
    """Register the given username with the server, from the client.
       IMPORTANT: don't forget to send 'r'!

    PARAMETERS
    ==========
    ip: The IP address to connect to, as a string.
    port: The port to connect to, as an int.
    username: The username to register, as a string.
    pw: The password, as a string.
    s: The salt, a bytes object 16 bytes long.

    RETURNS
    =======
    If successful, return a tuple of the form (N, g, v), all integers.
       On failure, return None.
    """
    try:
        sock = create_socket(ip, port, False)
        send(sock, b'r')
        N = receive(sock, 64)
        g = receive(sock,64)
        x = calc_x(s, pw)
        v = calc_A(N, g, x)
        send(sock, int_to_bytes(len(username),1))
        send(sock, username.encode('utf-8'))
        send(sock, s)
        send(sock, int_to_bytes(v,64))
        return (bytes_to_int(N), bytes_to_int(g), v)
    except:
        print("Unexpected error:", sys.exc_info())
        return None

def server_register( sock, N, g, database ):
    """Handle the server's side of the registration. IMPORTANT: reading the
       initial 'r' has been handled for you.

    PARAMETERS
    ==========
    sock: A socket object that contains the client connection.
    N: A safe prime. Could be an integer or bytes object.
    g: A primitive root of the safe prime. Could be an integer or bytes object.
    database: A dictionary of all registered users. The keys are usernames
       (as strings!), and the values are tuples of the form (s, v), where s
       is the salt (16 bytes) and v is as per the assignment (integer).

    RETURNS
    =======
    If the registration process was successful, return an updated version of the
       database. If it was not, return None. NOTE: a username that tries to
       re-register with a different salt and password is likely malicious,
       and should therefore count as an unsuccessful registration that doesn't
       modify the user database.
    """
    #TEST, READ NOTE AND MODIFY FUNCTION.
    if type(N) == int:
        N = int_to_bytes(N, 64)
    if type(g) == int:
        g = int_to_bytes(g, 64)
    try:
        send(sock, N)
        send(sock, g)
        usernameLength = receive(sock, 1)
        username = receive(sock, bytes_to_int(usernameLength))
        username = username.decode('utf-8')
        if username in database:
            return None
        s = receive(sock, 16)
        v = receive(sock, 64)
        database[username] = (s, bytes_to_int(v))
        sock.close()
        return database
    except:
        print("Unexpected error:", sys.exc_info())
        return None

def client_protocol( ip, port, N, g, username, pw, s ):
    """Register the given username with the server, from the client.
       IMPORTANT: don't forget to send 'p'!

    PARAMETERS
    ==========
    ip: The IP address to connect to, as a string.
    port: The port to connect to, as an int.
    N: A safe prime. Could be an integer or bytes object.
    g: A primitive root of the safe prime. Could be an integer or bytes object.
    username: The username to register, as a string.
    pw: The password, as a string.
    s: The salt, a bytes object 16 bytes long. Must match what the server 
       sends back.

    RETURNS
    =======
    If successful, return a tuple of the form (a, K_client), where both a and 
       K_client are integers. If not, return None.
    """
    try:
        sock = create_socket(ip, port, False)
        send(sock, b'p')

        #REDUCED a FOR TESTING FIX LATER, 3 SHOUDL BE 63
        a = int.from_bytes(os.urandom(3), byteorder="big")

        A = calc_A(N, g, a)
        A = int_to_bytes(A, 64)

        send(sock, int_to_bytes(len(username),1)) #1
        send(sock, username.encode('utf-8')) #2
        send(sock, A) #3
        s = receive(sock, 16) #4
        B = receive(sock, 64) #5

        u = calc_u(A, B)
        x = calc_x(s, pw)
        v = calc_A(N, g, x)

        #where is k? I already calculated it.......
        byteN = N
        byteG = g
        if type(byteN) == int:
            byteN = int_to_bytes(byteN,64)
        if type(byteG) == int:
            byteG = int_to_bytes(byteG,64)
        byteK = hash_bytes(byteN + byteG)
        k = int.from_bytes(byteK, "big")

        K_client = calc_K_client(N, B, k, v, a, u, x)

        M1 = calc_M1(A, B, K_client)
        send(sock, M1) #6

        M2 = receive(sock, 32) #7
        M2check = calc_M2(A, M1, K_client)
        if M2 != M2check:
            return None
        return (a, K_client)
    except:
        print("Unexpected error:", sys.exc_info())
        return None



def server_protocol( sock, N, g, database ):
    """Handle the server's side of the consensus protocal. 
       IMPORTANT: reading the initial 'p' has been handled for 
       you.

    PARAMETERS
    ==========
    sock: A socket object that contains the client connection.
    N: A safe prime. Could be an integer or bytes object.
    g: A primitive root of the safe prime. Could be an integer or bytes object.
    database: A dictionary of all registered users. The keys are usernames
       (as strings!), and the values are tuples of the form (s, v), where s
       is the salt (16 bytes) and v is as per the assignment (integer).

    RETURNS
    =======
    If successful, return a tuple of the form (username, b, K_server), where both b and 
       K_server are integers while username is a string. If not, return None.
    """
    try:
        #REDUCED b FOR TESTING FIX LATER, 3 SHOUDL BE 63
        b = int.from_bytes(os.urandom(3), byteorder="big")

        usernameLength = receive(sock, 1) #1
        username = receive(sock, bytes_to_int(usernameLength)) #2
        username = username.decode('utf-8')

        A = receive(sock, 64) #3
        print("recieving A:")
        print(len(A))
        s, v = database[username]
        
        #where is k? I already calculated it.......
        byteN = N
        byteG = g
        if type(byteN) == int:
            byteN = int_to_bytes(byteN,64)
        if type(byteG) == int:
            byteG = int_to_bytes(byteG,64)
        byteK = hash_bytes(byteN + byteG)
        k = int.from_bytes(byteK, "big")


        B = calc_B(N, g, b, k, v)
        send(sock, bytes(s)) #4
        send(sock, int_to_bytes(B, 64)) #5

        u = calc_u(A, B)

        K_server = calc_K_server(N, A, b, v, u)

        M1 = receive(sock, 32) #6
        M1check = calc_M1(A, B, K_server)
        if M1 != M1check:
            sock.close()
            return None
        M2 = calc_M2(A, M1, K_server)
        send(sock, M2) #7

        sock.close()
        return (username, b, K_server)
    except:
        print("Unexpected error:", sys.exc_info())
        return None


##### MAIN

if __name__ == '__main__':
    '''
    if sys.argv[1] == '1' :
        N = 6738429807937222910210526874616251941443382359166392079528239786677121085534989603567400908198918212653384739417400283522479742444741328838214521974028099
        g = 2
        k = 74184672972276785240493288644147355832357041414362546492328570251674988486557
        # N, g, k = server_prepare()
        database = dict()
        sock = create_socket('127.0.4.18', 3180, True)
        while(1):
            client, addr = sock.accept()
            print("client connected")
            keyletter = receive(client,1)
            print("letter received:")
            print(keyletter)
            if(keyletter == b'r'):
                database = server_register(client, N, g, database)
                print('Server N:')
                print(N)
                print('Server g:')
                print(g)
                print('Server k:')
                print(k)
                print('Server db:')
                print(database)
            elif(keyletter == b'p'):
                username, b, K_Server = server_protocol(client, N, g, database)
                print('Server username:')
                print(username)
                print('Server b:')
                print(b)
                print('Server K_Server:')
                print(K_Server)
            else:
                print("WRONG LETTER: ")
                print(keyletter)
    if sys.argv[1] == '2':
        s = client_prepare()
        N, g, v = client_register('127.0.4.18', 3180, 'Daniel', 'BestPasswordEver', s)
        print('Client N:')
        print(N)
        print('Client g:')
        print(g)
        print('Client v:')
        print(v)
        a, K_client = client_protocol('127.0.4.18', 3180, N, g,'Daniel', 'BestPasswordEver', s)
        print('Client a:')
        print(a)
        print('Client K_client:')
        print(K_client)
    
    '''


    # parse the command line args
    cmdline = argparse.ArgumentParser( description="Test out a secure key exchange algorithm." )

    methods = cmdline.add_argument_group( 'ACTIONS', "The three actions this program can do." )

    methods.add_argument( '--client', metavar='IP:port', type=str, \
        help='Perform registration and the protocol on the given IP address and port.' )
    methods.add_argument( '--server', metavar='IP:port', type=str, \
        help='Launch the server on the given IP address and port.' )
    methods.add_argument( '--quit', metavar='IP:port', type=str, \
        help='Tell the server on the given IP address and port to quit.' )

    methods = cmdline.add_argument_group( 'OPTIONS', "Modify the defaults used for the above actions." )

    methods.add_argument( '--username', metavar='NAME', type=str, default="admin", \
        help='The username the client sends to the server.' )
    methods.add_argument( '--password', metavar='PASSWORD', type=str, default="swordfish", \
        help='The password the client sends to the server.' )
    methods.add_argument( '--salt', metavar='FILE', type=argparse.FileType('rb', 0), \
        help='A specific salt for the client to use, stored as a file. Randomly generated if not given.' )
    methods.add_argument( '--timeout', metavar='SECONDS', type=int, default=600, \
        help='How long until the program automatically quits. Negative or zero disables this.' )
    methods.add_argument( '-v', '--verbose', action='store_true', \
        help="Be more verbose about what is happening." )

    args = cmdline.parse_args()
    # handle the salt
    if args.salt:
        salt = args.salt.read( 16 )
    else:
        salt = client_prepare()

    if args.verbose:
        print( f"Program: Using salt <{salt.hex()}>" )
    
    # first off, do we have a timeout?
    killer = None           # save this for later
    if args.timeout > 0:
        # define a handler
        def shutdown( time, verbose=False ):
            sleep( time )
            if verbose:
                print( "Program: exiting after timeout.", flush=True )

            return # optional, but I like having an explicit return

        # launch it
        if args.verbose:
            print( "Program: Launching background timeout.", flush=True )
        killer = Process( target=shutdown, args=(args.timeout,args.verbose) )
        killer.daemon = True
        killer.start()

    # next off, are we launching the server?
    result      = None     # pre-declare this to allow for cascading

    server_proc = None
    if args.server:
        if args.verbose:
            print( "Program: Attempting to launch server.", flush=True )
        result = split_ip_port( args.server )

    if result is not None:

        IP, port = result
        if args.verbose:
            print( f"Server: Asked to start on IP {IP} and port {port}.", flush=True )
            print( f"Server: Generating N and g, this will take some time.", flush=True )
        N, g, k = server_prepare() 
        if args.verbose:
            print( f"Server: Finished generating N and g.", flush=True )

        # use an inline routine as this doesn't have to be globally visible
        def server_loop( IP, port, N, g, k, verbose=False ):
            
            database = dict()           # for tracking registered users

            sock = create_socket( IP, port, listen=True )
            if sock is None:
                if verbose:
                    print( f"Server: Could not create socket, exiting.", flush=True )
                return

            if verbose:
                print( f"Server: Beginning connection loop.", flush=True )
            while True:

                (client, client_address) = sock.accept()
                if verbose:
                    print( f"Server: Got connection from {client_address}.", flush=True )

                mode = receive( client, 1 )
                if len(mode) != 1:
                    if verbose:
                        print( f"Server: Socket error with client, closing it and waiting for another connection.", flush=True )
                    client.shutdown(socket.SHUT_RDWR)
                    client.close()
                    continue

                if mode == b'q':
                    if verbose:
                        print( f"Server: Asked to quit by client. Shutting down.", flush=True )
                    client.shutdown(socket.SHUT_RDWR)
                    client.close()
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                    return

                elif mode == b'r':
                    if verbose:
                        print( f"Server: Asked to register by client.", flush=True )

                    temp = server_register( client, N, g, database )
                    if (temp is None) and verbose:
                            print( f"Server: Registration failed, closing socket and waiting for another connection.", flush=True )
                    elif temp is not None:
                        if verbose:
                            print( f"Server: Registration complete, current users: {[x for x in temp]}.", flush=True )
                        database = temp

                elif mode == b'p':
                    if verbose:
                        print( f"Server: Asked to generate shared secret by client.", flush=True )

                    temp = server_protocol( client, N, g, database )
                    if (temp is None) and verbose:
                            print( f"Server: Protocol failed, closing socket and waiting for another connection.", flush=True )
                    elif type(temp) == tuple:
                        if verbose:
                            print( f"Server: Protocol complete, negotiated shared key for {temp[0]}.", flush=True )
                            print( f"Server:  Shared key is {temp[2]}.", flush=True )

                # clean up is done inside the functions
                # loop back

        # launch the server
        if args.verbose:
            print( "Program: Launching server.", flush=True )
        p = Process( target=server_loop, args=(IP, port, N, g, k, args.verbose) )
        p.daemon = True
        p.start()
        server_proc = p

    # finally, check if we're launching the client
    result      = None     # clean this up

    client_proc = None
    if args.client:
        if args.verbose:
            print( "Program: Attempting to launch client.", flush=True )
        result = split_ip_port( args.client )

    if result is not None:

        IP, port = result
        if args.verbose:
            print( f"Client: Asked to connect to IP {IP} and port {port}.", flush=True )
        # another inline routine
        def client_routine( IP, port, username, pw, s, verbose=False ):

            if verbose:
                print( f"Client: Beginning registration.", flush=True )

            results = client_register( IP, port, username, pw, s )
            if results is None:
                if verbose:
                    print( f"Client: Registration failed, not attempting the protocol.", flush=True )
                return
            else:
                N, g, v = results
                if verbose:
                    print( f"Client: Registration successful, g = {g}.", flush=True )

            if verbose:
                print( f"Client: Beginning the shared-key protocol.", flush=True )

            results = client_protocol( IP, port, N, g, username, pw, s )
            if results is None:
                if verbose:
                    print( f"Client: Protocol failed.", flush=True )
            else:
                a, K_client = results
                if verbose:
                    print( f"Client: Protocol successful.", flush=True )
                    print( f"Client:  K_client = {K_client}.", flush=True )

            return

        # launch the server
        if args.verbose:
            print( "Program: Launching client.", flush=True )
        p = Process( target=client_routine, args=(IP, port, args.username, args.password, salt, args.verbose) )
        p.daemon = True
        p.start()
        client_proc = p
        

    # finally, the quitting routine
    result      = None     # clean this up

    if args.quit:
        # defer on the killing portion, in case the client is active
        result = split_ip_port( args.quit )

    if result is not None:

        IP, port = result
        if args.verbose:
            print( f"Quit: Asked to connect to IP {IP} and port {port}.", flush=True )
        if client_proc is not None:
            if args.verbose:
                print( f"Quit: Waiting for the client to complete first.", flush=True )
            client_proc.join()

        if args.verbose:
            print( "Quit: Attempting to kill the server.", flush=True )

        # no need for multiprocessing here
        sock = create_socket( IP, port )
        if sock is None:
            if args.verbose:
                print( f"Quit: Could not connect to the server to send the kill signal.", flush=True )
        else:
            count = send( sock, b'q' )
            if count != 1:
                if args.verbose:
                    print( f"Quit: Socket error when sending the signal.", flush=True )
            elif args.verbose:
                    print( f"Quit: Signal sent successfully.", flush=True )

            sock.shutdown(socket.SHUT_RDWR)
            sock.close()

    # finally, we wait until we're told to kill ourselves off, or both the client and server are done
    while not ((server_proc is None) and (client_proc is None)):

        if not killer.is_alive():
            if args.verbose:
                print( f"Program: Timeout reached, so exiting.", flush=True )
            if client_proc is not None:
                client_proc.terminate()
            if server_proc is not None:
                server_proc.terminate()
            exit()

        if (client_proc is not None) and (not client_proc.is_alive()):
            if args.verbose:
                print( f"Program: Client terminated.", flush=True )
            client_proc = None
        
        if (server_proc is not None) and (not server_proc.is_alive()):
            if args.verbose:
                print( f"Program: Server terminated.", flush=True )
            server_proc = None
            

#    exit()

