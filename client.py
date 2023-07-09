# This is an example from "Computer Networking: A Top Down Approach" textbook chapter 2
import socket
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
def initial_connection_protocol(clientSocket):
    # This is the server client communication protocol for when the initial connection

    # Creates the key and cipher from the server public key
    f = open("server_public.pem", "rb")
    server_pub = RSA.importKey(f.read())
    f.close()
    cipher_rsa_server = PKCS1_OAEP.new(server_pub)

    # Enters and sends the username
    username = input("Enter Username:")
    encrypted = cipher_rsa_server.encrypt(username.encode("ascii"))
    clientSocket.send(encrypted)

    # Enters and sends the password
    password = input("Enter Password:")
    encrypted = cipher_rsa_server.encrypt(password.encode("ascii"))
    clientSocket.send(encrypted)

    # Receives the Response
    response = clientSocket.recv(2048)
    if response.decode('ascii') == "Invalid Username or Password":
        print("Invalid Username or Password\nTerminating")
        return False, None
    else:
        # Creates the public key for the client and cipher from the client public key
        f = open(f"{username}_private.pem", "rb")
        client_pri = RSA.importKey(f.read())
        f.close()
        private_rsa_client = PKCS1_OAEP.new(client_pri)

        # Receives the symmetric key from the server
        sym_key = private_rsa_client.decrypt(response).decode("ascii")
        # noinspection PyTypeChecker
        sym_cipher = AES.new(sym_key, AES.MODE_ECB)

        # Sends the OK to the server
        encrypted = sym_cipher.encrypt("OK".encode("ascii"))
        clientSocket.send(encrypted)

        return True, sym_key





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
        
        initial_connection_protocol(clientSocket)
        
        # Client terminate connection with the server
        clientSocket.close()
        
    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

#----------
client()
