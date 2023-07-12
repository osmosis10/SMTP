# This is an example from "Computer Networking: A Top Down Approach" textbook chapter 2
# You can try this with nc localhost 12000 Test

import socket
import sys
import os, glob, datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

#Use this to generate RSA public and private keys
def generate_keys():
    private_key = RSA.generate(2048)
    public_key = private_key.public_key()
    return private_key, public_key

#Use this to generate a sym_key of size 32(256bits)
#Can change size to change the size of the key
def generate_sym_key(size=32):
    return get_random_bytes(size)

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
def export_private_key(private_key):
    with open(f'server_private.pem', 'wb') as file:
        file = file.write(private_key.export_key('PEM'))
    return

#Use this to save the server public key as a pem file to the current
#directory
def export_public_key(public_key):
    with open(f'server_public.pem', 'wb') as file:
        file = file.write(public_key.export_key('PEM'))
    return

#User this to save the server public key binary to a variable
def import_public_key():
    with open('server_public.pem', 'rb') as file:
        server_public_key = file.read()
    return server_public_key

#Use this to encrypt public_key which was generated via RSA
#public key is then encrypted with the sym_key
def encrypt_key(public_key, sym_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_sym_key = cipher.encrypt(sym_key)
    return encrypted_sym_key

#Use this to encrypt any messages that are need to be sent to the user
#message is encrypted via AES using the sym_key
def encrypt_message(message, sym_key):
    binary_message = message.encode('utf-8')
    padded_message = pad(binary_message, 16)
    cipher_message = AES.new(sym_key, AES.MODE_ECB)
    encrypted_message = cipher_message.encrypt(padded_message)
    return encrypted_message

#Gives you a string representation of the encrypted sym key
def print_encrypted_sym(encrypted_sym_key):
    encrypted_sym_key_hex = ''.join([format(byte, '02x') for byte in encrypted_sym_key])
    print('SYMMETRIC KEY (HEX): ', encrypted_sym_key_hex)
    return

def server():
    #Server port
    serverPort = 12000
    
    #Create server socket that uses IPv4 and TCP protocols 
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in server socket creation:',e)
        sys.exit(1)
    
    #Associate 12000 port number to the server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:',e)
        sys.exit(1)        
        
    print('The server is ready to accept connections')
        
    #The server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(5)
        
    while 1:
        try:
            #Server accepts client connection
            connectionSocket, addr = serverSocket.accept()
            print(addr,'   ',connectionSocket)
            pid = os.fork()
            
            # If it is a client process
            if  pid== 0:
                
                serverSocket.close() 
                
                #Receive the client public key binary data
                client_public_key_data = connectionSocket.recv(4096)
                
                #Save it to client_public.pem for now
                with open('client_public.pem', 'wb') as file:
                    file.write(client_public_key_data)
                
                #Read it back as binary and save in a variable
                #For now i save the client key as client_public.pem
                #Once we have the code for receiving the username you can 
                #Most likely use the below commented out code to save the
                #individual clients
                #with open(f'{username}_public.pem', 'rb') as file:
                    #client_public_key = RSA.import_key(file.read())
                with open('client_public.pem', 'rb') as file:
                    client_public_key = RSA.import_key(file.read())

                #Generate a sym_key, default size is 32 bytes (256 bits) but 
                #can change through by inputting desired size as parameter
                sym_key = generate_sym_key()
                
                #Encrypt out sym_key using the received client public key and out generated sym_key
                encrypted_sym_key = encrypt_key(client_public_key, sym_key)
              
                #Send out encrypted sym_key to client
                connectionSocket.send(encrypted_sym_key)
                
                #Generate out server's public and private keys
                private_key, public_key = generate_keys()
                
                #Save the public and private keys in current directory
                export_private_key(private_key)
                export_public_key(public_key)
                
                #Recieve the dummy message, temporary
                connectionSocket.recv(2048).decode('ascii')
                
                #Save the server_public key in binary
                server_public_key = import_public_key()
                
                #Send the server public key binary to the client
                connectionSocket.send(server_public_key)
        
                
                #Server send a message to the client
                connectionSocket.send("Enter a message: ".encode('ascii'))
                
                #Server receives client message, decode it and convert it to upper case
                message = connectionSocket.recv(2048)
                modifiedMessage = message.decode('ascii').upper()
                
                #Server sends the client the modified message
                print(modifiedMessage)
                connectionSocket.send(modifiedMessage.encode('ascii'))
                
                connectionSocket.close()
                
                return
            
            #Parent doesn't need this connection
            connectionSocket.close()
            
        except socket.error as e:
            print('An error occured:',e)
            serverSocket.close() 
            sys.exit(1)        
        except Exception as e:
            print('Error: ', e)
            serverSocket.close() 
            sys.exit(0)
            
        
#-------
server()
#private_key, public_key = generate_keys()
#export_private_key(private_key)
#export_public_key(public_key)