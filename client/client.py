# This is an example from "Computer Networking: A Top Down Approach" textbook chapter 2
import socket
import sys
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
def generate_keys():
    private_key = RSA.generate(2048)
    public_key = private_key.public_key()
    return private_key, public_key
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

def encrypt_message(message, sym_key):
    binary_message = str(message).encode('utf-8')
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

def file_length(file):
    with open(file, "r") as f:
        content = f.read()
        length = len(content)
        return length
    
def file_generator(path, num_characters):
    with open(path, 'w') as file:
        for i in range(num_characters):
            file.write(chr(65 + (i % 26)))
    
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
        return False, None, username
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

        return True, sym_key, username


def read_lines():
    lines = ""
    
    while True:
        line = input()
        


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
        
        accepted_connection, sym_key, username = initial_connection_protocol(clientSocket)
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
                    message = clientSocket.recv(2048)
                    print(decrypt_message(message,sym_key))
                    dest = input("Enter destinations (separated by ;): ")
                    while dest.strip() == "":
                        print("Invalid input. Please enter at least one destination.")
                        dest = input("Enter destinations (separated by ;): ")
                    title = input("Enter title: ")
                    while title.strip() == "":
                        print("Invalid input. Do not leave empty.")
                        title = input("Enter title: ")
                    load_file = input("Would you like to load contents from a file?(Y/N) " )
                    while load_file.upper() not in ("N", "Y"):
                        if load_file.strip() == "":
                            print("Invalid input. Do not leave empty.")
                            load_file = input("Would you like to load contents from a file?(Y/N) ")
                        else:
                            print("Invalid input.")
                            load_file = input("Would you like to load contents from a file?(Y/N) ")
                    if (load_file.upper() == "Y"):
                        content = input("Enter filename: ")
                        length = file_length(content)
                        if (length > 1000000):
                            print("File size is too large (>1mB)")
                            while True:
                                content = input("Enter filename: ")
                                length = file_length(content)
                                if (length <= 1000000):
                                    break
                                else:
                                    print("File size is too large (>1mB)")
                        with open(content, 'r') as file:
                            content = file.read()
                            #print(content)
                    elif (load_file.upper() == "N"): #We don't have a limit check when the user inputs text, as we assume they will not go paste the terminal limit of 4095 characters
                        content = input("Enter message contents: ")
                        length = len(content) 
                    email = f'\033[1mFrom:\033[0m {username}\n' \
                                f'\033[1mTo:\033[0m {dest}\n' \
                                f'\033[1mTime and Date:\033[0m\n' \
                                f'\033[1m\033[1mTitle:\033[0m {title}\n'\
                                f'\033[1mContent Length:\033[0m {length}\n' \
                                f'\033[1mContent:\033[0m {content}\n'
                    print("The message is sent to the server.")
                    encrypted_email = encrypt_message(email,sym_key)
                    
                    clientSocket.send(encrypt_message((str(len(encrypted_email))), sym_key))
                    ok = clientSocket.recv(2048)
                    ok = decrypt_message(ok, sym_key)
                    offset = 0
                    #The code below sends our email from above in chunks to better handle large file sizes
                    while offset < len(encrypted_email):
                        remaining = len(encrypted_email) - offset #Remaining size of email
                        chunk_size = min(4096, remaining) #chunk_size is the minimum of the buffer(4096) or remaining(Size of remaining email)
                        chunk = encrypted_email[offset:offset + chunk_size] #Takes characters from the offset to the offset and chunk_size
                        clientSocket.send(chunk)
                        offset += chunk_size #Adds the chunk_size to offset
                        
                    #clientSocket.send(encrypt_message(email, sym_key))
                elif command == "2":
                    # Recieving size
                    size = clientSocket.recv(2048)
                    size_decrypt = int(decrypt_message(size, sym_key))
                    clientSocket.send(encrypt_message("OK", sym_key)) # Send ok
                    
                    
                    
                    num_bytes = 0  # var for bytes length
                    inbox = b"" # var for bytes
                    
                    while num_bytes < size_decrypt:
                        chunk = clientSocket.recv(2048) # chunks to be recieved
                        
                        inbox += chunk # total message being added to
                        num_bytes += len(inbox) # total # of bytes recieved
                    
                    inbox_decrypt = decrypt_message(inbox, sym_key) # decrypt and decode
                    print(inbox_decrypt)
                    
                elif command == "3":
                    index_request = clientSocket.recv(2048)
                    index_request = decrypt_message(index_request,sym_key)
                    print(index_request)
                    
                    index = input("Enter the email index you wish to view: ")
                    while index.strip() == "" or not index.isdigit():
                        print("Invalid input. Please enter an index from the options above.")
                        index = input("Enter the email index you wish to view: ")
                    clientSocket.send(encrypt_message(index, sym_key))
                    
                    email_length = clientSocket.recv(2048) #Length of server side encrypted email
                    email_length = decrypt_message(email_length, sym_key)
                    
                    clientSocket.send(encrypt_message("ok", sym_key))
                    
                    email = b''
                    #The while loop below receives our email in chunks until the length of the email variable is the same as the email_length
                    while len(email) < int(email_length):
                        data = clientSocket.recv(4096)
                        email += data
                    
                    print(decrypt_message(email, sym_key))
                    
                    


        # Client terminate connection with the server
        clientSocket.close()
        print("The connection is terminated with the server")

    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)
#----------
client()
#file_path = 'test_file3.txt'
#num_characters = 1000001
#file_generator(file_path, num_characters)
#with open(file_path, "r") as file:
#    print(len(file.read()))



