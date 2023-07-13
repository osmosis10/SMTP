# This is an example from "Computer Networking: A Top Down Approach" textbook chapter 2
import socket
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

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
def export_private_key(private_key, username='john'):
    with open(f'{username}_private.pem', 'wb') as file:
        file = file.write(private_key.export_key('PEM'))
    return


# Use this to save the server public key as a pem file to the current
# directory
def export_public_key(public_key, username='john'):
    with open(f'{username}_public.pem', 'wb') as file:
        file = file.write(public_key.export_key('PEM'))
    return


# Read in the public key as binary and save in a variable
def import_public_key(username='john'):
    with open(f'{username}_public.pem', 'rb') as file:
        client_public_key = file.read()
    return client_public_key

# Read in the private key as binary and save in a variable
def import_private_key(username='john'):
    with open(f'{username}_private.pem', 'rb') as file:
        client_public_key = file.read()
    return client_public_key


# Gives you a string representation of the encrypted sym key
def print_encrypted_sym(encrypted_sym_key):
    encrypted_sym_key_hex = ''.join([format(byte, '02x') for byte in encrypted_sym_key])
    print('SYMMETRIC KEY (HEX): ', encrypted_sym_key_hex)
    return

def initial_connection_protocol(clientSocket):
    # This is the server client communication protocol for when the initial connection

    # Creates the key and cipher from the server public key
    server_pub = RSA.importKey(import_public_key("server"))
    cipher_rsa_server = PKCS1_OAEP.new(server_pub)

    # Enters and sends the username
    username = input("Enter Username: ")
    encrypted = cipher_rsa_server.encrypt(username.encode("ascii"))
    clientSocket.send(encrypted)

    # Enters and sends the password
    password = input("Enter Password: ")
    encrypted = cipher_rsa_server.encrypt(password.encode("ascii"))
    clientSocket.send(encrypted)

    # Receives the Response
    response = clientSocket.recv(2048)
    try:
        reply = response.decode('ascii')
        print(f"{reply}\nTerminating")
        return False, None
    except Exception:

        # Creates the private key for the client and cipher from the client public key
        client_pri = RSA.importKey(import_private_key(username))
        private_rsa_client = PKCS1_OAEP.new(client_pri)

        # Receives the symmetric key from the server
        sym_key = private_rsa_client.decrypt(response)
        sym_cipher = AES.new(sym_key, AES.MODE_ECB)

        # Sends the OK to the server
        encrypted = sym_cipher.encrypt(pad("OK".encode("ascii"), 16))
        clientSocket.send(encrypted)

        return True, sym_key





def client():
    # Server Information
    serverName = '127.0.0.1' #'localhost'
    serverPort = 13000
    
    #Create client socket that useing IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)    
    
    try:
        #Client connect with the server
        clientSocket.connect((serverName,serverPort))
        
        accepted_connection, sym_key = initial_connection_protocol(clientSocket)
        if accepted_connection:
            # noinspection PyTypeChecker
            sym_cipher = AES.new(sym_key, AES.MODE_ECB)

            command = "0"
            # Loops until the command is 4 (exit)
            while command != "4":
                # Gets instructions from the server
                encrypted = clientSocket.recv(2048)
                instructions = unpad(sym_cipher.decrypt(encrypted), 16).decode("ascii")
                print(instructions)
                command = input("choice: ")

                # Sends command to the server
                encrypted = sym_cipher.encrypt(pad(command.encode('ascii'), 16))
                clientSocket.send(encrypted)

                if command == "1":
                    print("THIS IS WHERE EMAIL CREATION CLIENT GOES\n")
                elif command == "2":
                    print("THIS IS WHERE INBOX DISPLAY CLIENT GOES\n")
                elif command == "3":
                    print("THIS IS WHERE EMAIL DISPLAY CLIENT GOES\n")
        
        # Client terminate connection with the server
        clientSocket.close()
        
    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

#----------
client()
