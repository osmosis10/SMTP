# This is an example from "Computer Networking: A Top Down Approach" textbook chapter 2
import socket
import sys
import os, glob, datetime
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

#Use this to generate RSA public and private keys
def generate_keys():
    private_key = RSA.generate(2048)
    public_key = private_key.public_key()
    return private_key, public_key

#You can use this to print out the public and private keys
#The commented out parts will print out the modulus and exponent
#components of the key (n=modulus, e,d = exponent)
def print_keys(private_key, public_key):
    #Print out the modulus of the private key
    #print(f'Start private_key.n {private_key.n} Stop private_key.n\n')
    #Print out the exponent of the private key
    #print(f'Start private_key.d {private_key.d} Stop private_key.d\n')
    #Print out the modulus of the public key
    #print(f'Start public_key.n {public_key.n} Stop public_key.n\n')
    #Print out the exponent of the public key
    #print(f'Start public_key.e {public_key.e} Stop public_key.e\n')
    
    private_key_pem = private_key.export_key()
    public_key_pem = public_key.export_key()
    
    print(private_key_pem)
    print(public_key_pem)
    return

#Use this to save the server private key as a pem file to the current
#directory
def export_private_key(private_key, username='john'):
    with open(f'{username}_private.pem', 'wb') as file:
        file = file.write(private_key.export_key('PEM'))
    return

#Use this to save the server public key as a pem file to the current
#directory
def export_public_key(public_key, username='john'):
    with open(f'{username}_public.pem', 'wb') as file:
        file = file.write(public_key.export_key('PEM'))
    return

#Read in the public key as binary and save in a variable
def import_public_key(public_key, username='john'):
    with open(f'{username}_public.pem', 'rb') as file:
        client_public_key = file.read()
    return client_public_key
    
#Gives you a string representation of the encrypted sym key
def print_encrypted_sym(encrypted_sym_key):
    encrypted_sym_key_hex = ''.join([format(byte, '02x') for byte in encrypted_sym_key])
    print('SYMMETRIC KEY (HEX): ', encrypted_sym_key_hex)
    return

def client():
    # Server Information
    serverName = '127.0.0.1' #'localhost'
    serverPort = 12000
    
    #Create client socket that useing IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)    
    
    try:
        #Client connect with the server
        clientSocket.connect((serverName,serverPort))
        
        #Generate client private and public keys
        private_key, public_key = generate_keys()
    
        #Save them in directory
        export_private_key(private_key)
        export_public_key(public_key)
    
        #Save binary key data in client_public_key
        client_public_key = import_public_key(public_key)
        
        #Send the key to the server
        clientSocket.send(client_public_key)

        #recieving the server_public_key
        encrypted_sym_key = clientSocket.recv(4096)

        #Decrypt the encrypted_sym_key
        cipher = PKCS1_OAEP.new(private_key)
        decrypted_sym_key = cipher.decrypt(encrypted_sym_key)
        
        #Temporary dummy message to continue the handshake
        #As we send the server key right after this
        dummy = clientSocket.send('dummy'.encode('ascii'))
        # Client receives a message and send it to the client
        
        #Receieve the server public key information
        server_public_key_data = clientSocket.recv(4096)
        
        #Save the server public key information to server_public.pem
        with open('server_public.pem', 'wb') as file:
            file.write(server_public_key_data)
        
        message = clientSocket.recv(2048).decode('ascii')
        
        #Client send message to the server
        message = input(message).encode('ascii')
        clientSocket.send(message)
        
        # Client receives a message from the server and print it
        message = clientSocket.recv(2048)
        print(message.decode('ascii'))
        
        # Client terminate connection with the server
        clientSocket.close()
        
    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

#----------
client()
#private_key, public_key = generate_keys()
#print_keys(private_key, public_key)
#export_private_key(private_key)
#export_public_key(public_key)
