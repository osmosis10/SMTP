# This is an example from "Computer Networking: A Top Down Approach" textbook chapter 2
# You can try this with nc localhost 12000 Test

import socket
import sys, glob, datetime
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def initial_connection_protocol(connectionSocket):
    # This is the server client communication protocol for when the initial connection

    # Creates the public key and cipher from the server public key
    f = open("server_public.pem", "rb")
    server_pub = RSA.importKey(f.read())
    f.close()
    public_rsa_server = PKCS1_OAEP.new(server_pub)

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

                initial_connection_protocol(connectionSocket)
                
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
