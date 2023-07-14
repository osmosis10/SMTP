# This is an example from "Computer Networking: A Top Down Approach" textbook chapter 2
# You can try this with nc localhost 12000 Test
import json
import socket
import sys, glob, datetime
import os
from datetime import datetime
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
def import_public_key(username):
    with open(f'{username}_public.pem', 'rb') as file:
        server_public_key = file.read()
    return server_public_key

# Read in the private key as binary and save in a variable
def import_private_key():
    with open(f'server_private.pem', 'rb') as file:
        client_public_key = file.read()
    return client_public_key


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

# Use this to decrypt any messages that are need to be sent to the user
# message is decrypted via AES using the sym_key
def decrypt_message(encrypted_message, sym_key):
    cipher_message = AES.new(sym_key, AES.MODE_ECB)
    decrypted_message = cipher_message.decrypt(encrypted_message)
    unpadded_message = unpad(decrypted_message, 16)
    message = unpadded_message.decode('utf-8')
    return message

# Gives you a string representation of the encrypted sym key
def print_encrypted_sym(encrypted_sym_key):
    encrypted_sym_key_hex = ''.join([format(byte, '02x') for byte in encrypted_sym_key])
    print('SYMMETRIC KEY (HEX): ', encrypted_sym_key_hex)
    return

def splice_word(string, target):
    start = string.find(target)
    middle = string.find(":", start)
    middle2 = string.find("m", middle)
    end = string.find("\n", middle2)
    
    return string[middle2+1:end].strip()

def initial_connection_protocol(connectionSocket):
    # This is the server client communication protocol for when the initial connection

    # Creates the private key and cipher from the server private key
    server_pri = RSA.importKey(import_private_key())
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
        client_pub = RSA.importKey(import_public_key(username))
        public_rsa_client = PKCS1_OAEP.new(client_pub)

        # Creates and sends the sym key
        sym_key = generate_sym_key()
        encrypted = public_rsa_client.encrypt(sym_key)
        connectionSocket.send(encrypted)

        print(f"Connection Accepted and Symmetric Key Generated for Client:{username}")

        # Receive OK (Not sure if this is what to do here, should ask in class)
        encrypted = connectionSocket.recv(2048)


        return True, sym_key, username
    else:
        # Sends denied connection in the clear
        connectionSocket.send("Invalid Username or Password".encode('ascii'))
        print(f"The received Client Information: {username} is invalid (Connection Terminated)")
        return False, None



def substring(string, delimiter):
    return string.partition(delimiter)[2]

# Bubble sort for dates
def bubblesort(elements):
    swapped = False
    for n in range(len(elements)-1, 0, -1):
        for i in range(n):
            if datetime.strptime(elements[i], '%Y-%m-%d %H:%M:%S') > datetime.strptime(elements[i + 1], '%Y-%m-%d %H:%M:%S'):
                swapped = True
                elements[i], elements[i + 1] = elements[i + 1], elements[i]       
        if not swapped:
            return

def server():
    # Server port
    serverPort = 13000

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

                accepted_connection, sym_key, username = initial_connection_protocol(connectionSocket)
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
                        encrypted = sym_cipher.encrypt(pad(instructions, 16))
                        connectionSocket.send(encrypted)

                        # Gets command from client
                        encrypted = connectionSocket.recv(2048)
                        command = unpad(sym_cipher.decrypt(encrypted), 16).decode("ascii")

                        if command == "1":
                            message = "Send this email\n"
                            connectionSocket.send(encrypt_message(message, sym_key))
                            
                            email = connectionSocket.recv(2048)
                            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                            
                            email = decrypt_message(email, sym_key)
                            email = email.replace("\033[1mTime and Date:\033[0m", f"\033[1mTime and Date:\033[0m {current_time}")
                            print(email)
                            
                            client = splice_word(email, "From")
                            dest = splice_word(email, "To")
                            length = splice_word(email, "Length")
                             
                            print(f"An email from {client} is sent to {dest} has content length of {length}")
                            title = splice_word(email, "Title")
                            
                            current_path = os.getcwd()
                            new_path = os.path.join(current_path, f'{client}', f'{client}_{title}.txt')
                            with open(new_path, "w") as file:
                                file.write(email)
 
                            
                        elif command == "2":
                            inbox = "\nIndex\tFrom\t\tDateTime\t\tTitle\n"
                            folder = username # folder for client
                            inbox_dict=  {} # dictionary for inbox data
                            list_of_lines = {}
                            filelist = os.listdir(folder) #list of files in folder
                            list_dates = []
                            
                            date_counter = 0
                            
                            #try:
                            for file in filelist:
                                path = os.path.join(folder, file) #path to each file in the directory ex. client1/client1_Greetings.txt
                                
                                # OBTAINING DATA FROM FILES
                                with open(path, "r") as email_file:
                                    lines = email_file.readlines() # stores every line in file
                                    print("INSIDE client1")
                                    for line in lines:
                                        print(line)
                                        if (line.startswith("[1mFrom:[0m ")):
                                            print("inside from")
                                            # delemits the line and saves name of senders
                                            client_sender = substring(line,"[1mFrom:[0m ").strip("\n")
                                            
                                            # delemits the line and saves name of sender
                                        elif (line.startswith("[1mTime and Date:[0m ")):
                                            print("inside tine")
                                            date = substring(line, "[1mTime and Date:[0m ").strip("\n")
                                            list_dates[date_counter] = date
                                            date_counter +=1
                                            
                                            # delemits the line and saves name of sender
                                        elif (line.startswith("[1m[1mTitle:[0m ")):
                                            print("inside Title")
                                            email_title = substring(line, "[1m[1mTitle:[0m ").strip("\n")

                                    # stores relevant data into dictionary to be used later
                                    inbox_dict[folder] = {"sender": client_sender, "date": date, "title": email_title}
                                    #print(inbox_dict) # testing
                                   
    
                                    
                            
                                    
            
                                    
                                    
                                    
                                    
            
                                        
                            
                            
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
