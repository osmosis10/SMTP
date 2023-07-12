# This is an example from "Computer Networking: A Top Down Approach" textbook chapter 2
# You can try this with nc localhost 12000 Test

import socket
import sys
import os, glob, datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


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