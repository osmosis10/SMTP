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


#You can use this to print out the public and private keys
#The commented out parts will print out the modulus and exponent
#components of the key (n=modulus, e,d = exponent)


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
