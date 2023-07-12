# This is an example from "Computer Networking: A Top Down Approach" textbook chapter 2
# You can try this with nc localhost 12000 Test
import json
import socket
import sys, glob, datetime
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# Use this to generate RSA public and private keys
def generate_keys():
    private_key = RSA.generate(2048)
    public_key = private_key.public_key()
    return private_key, public_key


# Use this to generate a sym_key of size 32(256bits)
# Can change size to change the size of the key
def generate_sym_key(size=32):
    return get_random_bytes(size)


# You can use this to print out the public and private keys
# The commented out parts will print out the modulus and exponent
# components of the key (n=modulus, e,d = exponent)
def print_keys(private_key, public_key):
    # Print out the modulus of the private key
    # print(f'Start private_key.n {private_key.n} Stop private_key.n\n')
    # Print out the exponent of the private key
    # print(f'Start private_key.d {private_key.d} Stop private_key.d\n')
    # Print out the modulus of the public key
    # print(f'Start public_key.n {public_key.n} Stop public_key.n\n')
    # Print out the exponent of the public key
    # print(f'Start public_key.e {public_key.e} Stop public_key.e\n')

    private_key_pem = private_key.export_key()
    public_key_pem = public_key.export_key()

    print(private_key_pem)
    print(public_key_pem)
    return


# Use this to save the server private key as a pem file to the current
# directory
def export_private_key(private_key):
    with open(f'server_private.pem', 'wb') as file:
        file = file.write(private_key.export_key('PEM'))
    return


# Use this to save the server public key as a pem file to the current
# directory
def export_public_key(public_key):
    with open(f'server_public.pem', 'wb') as file:
        file = file.write(public_key.export_key('PEM'))
    return


# User this to save the server public key binary to a variable
def import_public_key():
    with open('server_public.pem', 'rb') as file:
        server_public_key = file.read()
    return server_public_key


# Use this to encrypt public_key which was generated via RSA
# public key is then encrypted with the sym_key
def encrypt_key(public_key, sym_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_sym_key = cipher.encrypt(sym_key)
    return encrypted_sym_key


# Use this to encrypt any messages that are need to be sent to the user
# message is encrypted via AES using the sym_key
def encrypt_message(message, sym_key):
    binary_message = message.encode('utf-8')
    padded_message = pad(binary_message, 16)
    cipher_message = AES.new(sym_key, AES.MODE_ECB)
    encrypted_message = cipher_message.encrypt(padded_message)
    return encrypted_message


# Gives you a string representation of the encrypted sym key
def print_encrypted_sym(encrypted_sym_key):
    encrypted_sym_key_hex = ''.join([format(byte, '02x') for byte in encrypted_sym_key])
    print('SYMMETRIC KEY (HEX): ', encrypted_sym_key_hex)
    return


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
        # sym_key = sym_keygen()
        # encrypted = public_rsa_client.encrypt(sym_key.encode("ascii"))
        # connectionSocket.send(encrypted)

        # Generate Cipher
        # sym_cipher = AES.new(sym_key, AES.MODE_ECB)

        print(f"Connection Accepted and Symmetric Key Generated for Client:{username}")

        # Receive OK (Not sure if this is what to do here, should ask in class)
        encrypted = connectionSocket.recv(2048)
        # message = sym_cipher.decrypt(encrypted).decode("ascii")
        # print(f"{message} Recived")

        # return True, sym_key
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

                accepted_connection, sym_key = initial_connection_protocol(connectionSocket)
                if accepted_connection:
                    # noinspection PyTypeChecker
                    sym_cipher = AES.new(sym_key, AES.MODE_ECB)

                    command = "0"
                    # Loops until the command is 4 (exit)
                    while command != "4":
                        # Creates and sends the instructions
                        instructions = \
                            "Select the Operation:\n    " \
                            "1) Create and Send an Email\n    " \
                            "2) Display the Inbox List\n    " \
                            "3) Display the Email Contents\n    " \
                            "4) Terminate the Connection".encode('ascii')
                        encrypted = sym_cipher.encrypt(instructions)
                        connectionSocket.send(encrypted)

                        if command == "1":
                            print("THIS IS WHERE EMAIL CREATION SERVER GOES")
                        elif command == "2":
                            print("THIS IS WHERE INBOX DISPLAY SERVER GOES")
                        elif command == "3":
                            print("THIS IS WHERE EMAIL DISPLAY SERVER GOES")


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
