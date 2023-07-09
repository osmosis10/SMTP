# This is an example from "Computer Networking: A Top Down Approach" textbook chapter 2
# You can try this with nc localhost 12000 Test
import json
import socket
import sys, glob, datetime
import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def initial_connection_protocol(connectionSocket):
    # This is the server client communication protocol for when the initial connection

    # Creates the private key and cipher from the server private key
    f = open("server_private.pem", "rb")
    server_pri = RSA.importKey(f.read())
    f.close()
    private_rsa_server = PKCS1_OAEP.new(server_pri)

    # Receives the username
    encrypted = connectionSocket.recv(2048)
    username = private_rsa_server.decrypt(encrypted).decode("ascii")

    # Receives the Password
    encrypted = connectionSocket.recv(2048)
    password = private_rsa_server.decrypt(encrypted).decode("ascii")

    # Loads the user password json
    f = open("user_pass.json", "r")
    user_dict = json.loads(f.read())
    f.close()

    # Returns true for false if the username and password matches
    if username in user_dict.keys() and user_dict[username] == password:
        match = True
    else:
        match = False

    if match:
        # Creates the public key for the client and cipher from the client public key
        f = open(f"{username}_public.pem", "rb")
        client_pub = RSA.importKey(f.read())
        f.close()
        public_rsa_client = PKCS1_OAEP.new(client_pub)

        # Creates and sends the sym key
        #sym_key = sym_keygen()
        #encrypted = public_rsa_client.encrypt(sym_key.encode("ascii"))
        #connectionSocket.send(encrypted)

        # Generate Cipher
        #sym_cipher = AES.new(sym_key, AES.MODE_ECB)

        print(f"Connection Accepted and Symmetric Key Generated for Client:{username}")

        # Receive OK (Not sure if this is what to do here, should ask in class)
        encrypted = connectionSocket.recv(2048)
        #message = sym_cipher.decrypt(encrypted).decode("ascii")
        #print(f"{message} Recived")

        #return True, sym_key
    else:
        # Sends denied connection in the clear
        connectionSocket.send("Invalid Username or Password".encode('ascii'))
        print(f"The received Client Information: {username} is invalid (Connection Terminated)")
        return False, None







def server():
    # Server port
    serverPort = 12000

    # Create server socket that uses IPv4 and TCP protocols
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in server socket creation:', e)
        sys.exit(1)

    # Associate 12000 port number to the server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:', e)
        sys.exit(1)

    print('The server is ready to accept connections')

    # The server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(5)

    while 1:
        try:
            # Server accepts client connection
            connectionSocket, addr = serverSocket.accept()
            print(addr, '   ', connectionSocket)
            pid = os.fork()

            # If it is a client process
            if pid == 0:
                serverSocket.close()

                initial_connection_protocol(connectionSocket)

                connectionSocket.close()

                return

            # Parent doesn't need this connection
            connectionSocket.close()

        except socket.error as e:
            print('An error occured:', e)
            serverSocket.close()
            sys.exit(1)
        except Exception as e:
            print('Error: ', e)
            serverSocket.close()
            sys.exit(0)


# -------
server()
