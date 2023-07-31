# This is the enhanced with additional security client side of the SMTP program
# Conlan Myers - 3110785
# ADD other names here
import socket
import sys
import os
import json
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256, HMAC
from Crypto.Signature import pss
from Crypto.Util import Counter

# Use this to generate a sym_key of size 32(256bits)
# Can change size to change the size of the key
def generate_sym_key(size=32):
    return get_random_bytes(size)

def generate_HMAC(data, sym_key):
    try:
        with open('server_public.pem', 'rb') as file:
            server_pub = file.read()
        with open('client1_private.pem', 'rb') as file:
            client_priv = file.read()
    except FileNotFoundError:
        print("Error: Could not find 'server_public.pem'")
    except IOError as e:
        print(f"Error: Could not read 'server_public.pem': {e}")
    except Exception as e:
        print(f"Unexpected Error: {e}")
    mac = HMAC.new(sym_key, data.encode(), digestmod=SHA256)
    return mac

def generate_nonce(length=16):
    return get_random_bytes(length)
    
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

def encrypt_message_ctr(message,sym_key, nonce):
    ctr = Counter.new(64, prefix=nonce, little_endian=True, allow_wraparound=True)
    binary_message = str(message).encode('utf-8')
    padded_message = pad(binary_message, 16)
    cipher_message = AES.new(sym_key, AES.MODE_CTR, counter=ctr)
    encrypted_message = cipher_message.encrypt(padded_message)
    encrypted_payload = nonce + encrypted_message
    return encrypted_payload

# Use this to decrypt any messages that are need to be sent to the user
# message is decrypted via AES using the sym_key
def decrypt_message(encrypted_message, sym_key):
    cipher_message = AES.new(sym_key, AES.MODE_ECB)
    decrypted_message = cipher_message.decrypt(encrypted_message)
    unpadded_message = unpad(decrypted_message, 16)
    message = unpadded_message.decode('utf-8')
    return message

def decrypt_message_ctr(encrypted_payload, sym_key, nonce):
    nonce = encrypted_payload[:16]
    encrypted_message = encrypted_payload[16:]
    ctr = Counter.new(64, prefix=nonce, suffix=b'ABCD', little_endian=True, allow_wraparound=True)
    cipher_message = AES.new(sym_key, AES.MODE_CTR, counter=ctr)
    decrypted_message = cipher_message.decrypt(encrypted_message)
    unpadded_message = unpad(decrypted_message, 16)
    message = unpadded_message.decode('utf-8')
    return message, nonce

def file_length(file):
    with open(file, "r") as f:
        content = f.read()
        length = len(content)
        return length


def file_generator(path, num_characters):
    with open(path, 'w') as file:
        for i in range(num_characters):
            file.write(chr(65 + (i % 26)))

def test_nonce(clientSocket):
    sym_key = get_random_bytes(32)
    nonce = get_random_bytes(8)
    m1 = "Test Message 1"
    m2 = "Test Message 2"
    
    clientSocket.send(encrypt_message_ctr(m1, sym_key, nonce))
    nonce_response = decrypt_message(clientSocket.recv(2048), sym_key)
    print(nonce_response)
    
    clientSocket.send(encrypt_message_ctr(m2, sym_key, nonce))
    nonce_response = decrypt_message(clientSocket.recv(2048), sym_key)
    print(nonce_response)

def initial_connection_protocol(clientSocket):
    # This is the server client communication protocol for when the initial connection

    # Enters the username and password
    username = input("Enter Username: ")
    password = input("Enter Password: ")

    # Creates the key and cipher from the server public key
    server_pub = RSA.importKey(import_public_key("server"))
    cipher_rsa_server = PKCS1_OAEP.new(server_pub)

    # Creates, sends, and signs a hash for digital signature
    hash_sig = SHA256.new(username.encode("ascii"))
    print("Hash: ", hash_sig.digest())
    client_pri = RSA.importKey(import_private_key(username))
    signature = pss.new(client_pri)
    clientSocket.send(signature.sign(hash_sig))
    print("Signature: ",signature.sign(hash_sig))
    # Sends the username
    encrypted = cipher_rsa_server.encrypt(username.encode("ascii"))
    clientSocket.send(encrypted)

    # Sends the password
    encrypted = cipher_rsa_server.encrypt(password.encode("ascii"))
    clientSocket.send(encrypted)

    # Receives the Response
    response = clientSocket.recv(2048)
    try:
        reply = response.decode('ascii')
        print(f"{reply}\nTerminating")
        return False, None, username
    except UnicodeDecodeError:
        # Creates the Cipher from the client public key
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
        
def get_random_sequence():
    return int.from_bytes(os.urandom(4), byteorder="big")

def get_random_next():
    return int.from_bytes(os.urandom(1), byteorder="big")

#nonce = get_random_bytes(8)

def client():
    # Server Information
    serverName = input("Enter the server IP or name: ")
    serverPort = 13000

    # Create client socket that useing IPv4 and TCP protocols
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:', e)
        sys.exit(1)

    try:
        # Client connect with the server
        clientSocket.connect((serverName, serverPort))

        accepted_connection, sym_key, username = initial_connection_protocol(clientSocket)
        if accepted_connection:
            # noinspection PyTypeChecker
            sym_cipher = AES.new(sym_key, AES.MODE_ECB)

            command = "0"
            
            sequence_number = get_random_sequence()
            increment = get_random_next()
            clientSocket.send(encrypt_message(increment, sym_key))
            inbox_printed = 0
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
                
                #Protocol to send emails to other clients
                if command == "1":
                    message = clientSocket.recv(2048)
                    decrypt_message(message, sym_key)
                    #Clients that will receive the email
                    dest = input("Enter destinations (separated by ;): ")
                    #Check if empty
                    while dest.strip() == "":
                        print("Invalid input. Please enter at least one destination.")
                        dest = input("Enter destinations (separated by ;): ")
                    #Title of the email
                    title = input("Enter title: ")
                    #Check for some problematic characters and empty input
                    while title.strip() == "" or "/" in title or "\\" in title:
                        if title.strip() == "":
                            print("Invalid input. Do not leave empty.")
                        elif "/" in title or "\\" in title:
                            print("Invalid input: '/' or '\\")
                        #Title can be a max of 100 characters
                        elif len(title) > 100:
                            print("Invalid input. Max of 100 characters.")
                        title = input("Enter title: ")
                    #Client may choose to upload from a file or not
                    load_file = input("Would you like to load contents from a file?(Y/N) ")
                    #Check for case sensitive inpput and empty input
                    while load_file.upper() not in ("N", "Y"):
                        if load_file.strip() == "":
                            print("Invalid input. Do not leave empty.")
                            load_file = input("Would you like to load contents from a file?(Y/N) ")
                        else:
                            print("Invalid input.")
                            load_file = input("Would you like to load contents from a file?(Y/N) ")
                    #Check for if clients wants to upload a file
                    if (load_file.upper() == "Y"):
                        content = input("Enter filename: ")
                        if not (os.path.exists(content)):
                            print("File does not exist")
                            clientSocket.send(encrypt_message("Ok", sym_key))
                            continue
                        length = file_length(content)
                        #Max content length is 1,000,000 characters
                        if (length > 1000000):
                            print("Message length too long (max 1,000,000 characters)")
                            num_tries = 0
                            while num_tries != 2:
                                content = input("Enter filename: ")
                                length = file_length(content)
                                if (length <= 1000000):
                                    break
                                else:
                                    print("Message length too long (max 1,000,000 characters)")
                                num_tries += 1
                        if (num_tries == 3):
                            print("\nMax number of tries reached\n")
                            clientSocket.send(encrypt_message("Ok", sym_key))
                            continue
                        with open(content, 'r') as file:
                            content = file.read()
                    #Check for if client wants to input email themselves
                    elif (load_file.upper() == "N"):  # We don't have a limit check when the user inputs text, as we assume they will not go paste the terminal limit of 4095 characters
                        content = input("Enter message contents: ")
                        length = len(content)
                    email = f'\033[1mFrom:\033[0m {username}\n' \
                            f'\033[1mTo:\033[0m {dest}\n' \
                            f'\033[1mTime and Date:\033[0m\n' \
                            f'\033[1m\033[1mTitle:\033[0m {title}\n' \
                            f'\033[1mContent Length:\033[0m {length}\n' \
                            f'\033[1mContent:\033[0m {content}\n'
                    
                    #Random Nonce generated everytime a client sends an email
                    nonce = get_random_bytes(8)
                    print(nonce.hex(), "Nonce: Client Side")

                    #Timestamp of email creation
                    current = datetime.now()
                    timestamp = int(current.timestamp())
                    payload = {
                        'message': email,
                        'timestamp': timestamp
                    }
                    
                    #We serialize the payload so we can use it to generate a MAC
                    json_data = json.dumps(payload)
                    
                    #attacker_sym_key = get_random_bytes(32)
                    #mac = generate_HMAC(json_data, attacker_sym_key)
                    mac = generate_HMAC(json_data, sym_key)
                    print(mac.hexdigest(), "MAC: Client Side")
                    payload['mac'] = mac.hexdigest()
                    
                    #We serialize the payload again, as we added the MAC to it
                    json_mac_data = json.dumps(payload)
                      
                    print("The message is sent to the server.")
                    #We pass our new data, shared secret(sym_key) and the nonce into the 
                    #Counter mode encrpytion function
                    encrypted_email = encrypt_message_ctr(json_mac_data, sym_key, nonce)

                    #Send the length of our email over to the server
                    #used to receive correct number of bytes
                    clientSocket.send(encrypt_message((str(len(encrypted_email))), sym_key))
                    ok = clientSocket.recv(2048)
                    ok = decrypt_message(ok, sym_key)
                    offset = 0
                    # The code below sends our email from above in chunks to better handle large file sizes
                    while offset < len(encrypted_email):
                        remaining = len(encrypted_email) - offset  # Remaining size of email
                        chunk_size = min(4096,remaining)  # chunk_size is the minimum of the buffer(4096) or remaining(Size of remaining email)
                        chunk = encrypted_email[offset:offset + chunk_size]  # Takes characters from the offset to the offset and chunk_size
                        clientSocket.send(chunk)
                        offset += chunk_size  # Adds the chunk_size to offset

                    #Nonce Response can either be "Ok" or "Repeated Nonce. Rejecting Message."
                    #If its the latter than we print out the response and go back to the menu
                    nonce_response = decrypt_message(clientSocket.recv(2048), sym_key)
                    if nonce_response != "Ok":
                        print(nonce_response)
                        continue
                    clientSocket.send(encrypt_message("Ok", sym_key))
                    
                    #Mac Response can either be "Ok" or "Invalid MAC: Rejcting Message."
                    #If its the latter than we print out the response and go back to the menu
                    mac_response = decrypt_message(clientSocket.recv(2048), sym_key)
                    if mac_response != "Ok":
                        print(mac_response)
                        continue
                    clientSocket.send(encrypt_message("Ok", sym_key))
                    
                    #Timestamp Response can either be "Ok" or "Timestamp outdated. Please resubmit your request."
                    #If its the latter than we print out the response and go back to the menu
                    timestamp_response = decrypt_message(clientSocket.recv(2048), sym_key)
                    if timestamp_response != "Ok":
                        print(timestamp_response)
                        continue
                    clientSocket.send(encrypt_message("Ok", sym_key))
                    
                    #Valid response can either be "Ok" or a list of invalid clients
                    #Used in case the client submits destination clients that are not valid
                    valid_response = decrypt_message(clientSocket.recv(2048), sym_key)
                    if valid_response != "Ok":
                        print(valid_response)
                    clientSocket.send(encrypt_message("Ok", sym_key))
                    
                    sequence_number += increment
                if command == "2" or command == "3" and inbox_printed == 0:
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
                    inbox_printed += 1
                    
                if command == "3":
                    index_request = clientSocket.recv(2048)
                    index_request = decrypt_message(index_request, sym_key)

                    index = input("Enter the email index you wish to view: ")
                    while index.strip() == "" or not index.isdigit():
                        print("Invalid input. Please enter an index from the options above.")
                        index = input("Enter the email index you wish to view: ")
                    clientSocket.send(encrypt_message(index, sym_key))
                    
                    empty_folder_reponse = decrypt_message(clientSocket.recv(2048), sym_key)
                    if empty_folder_reponse != "Ok":
                        print(empty_folder_reponse)
                        clientSocket.send(encrypt_message("Ok", sym_key))
                        continue
                    clientSocket.send(encrypt_message("Ok", sym_key))
                    index_response = clientSocket.recv(2048)
                    index_response = decrypt_message(index_response, sym_key)
                    while index_response != "Ok":
                        index = input(index_response)
                        while index.strip() == "" or not index.isdigit():
                            index = input(index_response)
                        clientSocket.send(encrypt_message(index, sym_key))
                        index_response = clientSocket.recv(2048)
                        index_response = decrypt_message(index_response, sym_key)
                        if index_response == "Ok":
                            break
                    clientSocket.send(encrypt_message("Ok", sym_key))    
                    email_length = clientSocket.recv(2048)  # Length of server side encrypted email
                    email_length = decrypt_message(email_length, sym_key)

                    clientSocket.send(encrypt_message("ok", sym_key))

                    email = b''
                    # The while loop below receives our email in chunks until the length of the email variable is the same as the email_length
                    while len(email) < int(email_length):
                        data = clientSocket.recv(4096)
                        email += data

                    print(decrypt_message(email, sym_key))
                    clientSocket.send(encrypt_message("Ok", sym_key))

        # Client terminate connection with the server
        clientSocket.close()
        print("The connection is terminated with the server")

    except socket.error as e:
        print('An error occured:', e)
        clientSocket.close()
        sys.exit(1)


# ----------
client()
