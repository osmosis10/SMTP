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

# Gives you a string representation of the encrypted sym key
def print_encrypted_sym(encrypted_sym_key):
    encrypted_sym_key_hex = ''.join([format(byte, '02x') for byte in encrypted_sym_key])
    print('SYMMETRIC KEY (HEX): ', encrypted_sym_key_hex)
    return

#Made solely for finding our target words such as 'From' and 'To' from our email
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
            # datetime_obj1 = datetime.strptime(date_str1, '%Y-%m-%d %H:%M:%S')
            if datetime.strptime(elements[i], '%Y-%m-%d %H:%M:%S.%f') > datetime.strptime(elements[i + 1], '%Y-%m-%d %H:%M:%S.%f'):
                swapped = True
                elements[i], elements[i + 1] = elements[i + 1], elements[i]       
        if not swapped:
            return elements
        return elements

def inbox_data (filelist, folder):
    inbox_dict=  {} # dictionary for inbox data
    inbox_dict[folder] = {} # Nest inbox_dictionary


    list_dates = []  # list to store dates individually to be sorted
    email_names = [] # list to store email names
    num_files = 0    # counter for # of emails

    for file in filelist:
        path = os.path.join(folder, file) #path to each file in the directory ex. client1/client1_Greetings.txt
        email_names.append(file)
        
        # OBTAINING DATA FROM FILES
        with open(path, "r") as email_file:
            lines = email_file.readlines() # stores every line in file
            # reading each line in the email
            for line in lines:
                if (line.startswith("[1mFrom:[0m ")):
                    # delimits the line and saves name of SENDER
                    client_sender = substring(line,"[1mFrom:[0m ").strip("\n")
                    
                    # delimits the line and saves the DATE
                elif (line.startswith("[1mTime and Date:[0m ")):
                    date = substring(line, "[1mTime and Date:[0m ").strip("\n")
                    list_dates.append(date)

                    # delimits the line and saves the TITLE
                elif (line.startswith("[1m[1mTitle:[0m ")):
                    email_title = substring(line, "[1m[1mTitle:[0m ").strip("\n")


                # stores relevant data into dictionary to be used later
                # ex {client1: {greetings1.txt: {"sender": client_sender, ....}}}
            inbox_dict[folder][file] = {"sender": client_sender, "date": date, "title": email_title}
            num_files +=1
    
    return list_dates, email_names, num_files, inbox_dict

def server():
    # Server port
    serverPort = 12000

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

    email_list = [] #Email titles in sorted order
    
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
                            
                            email_length = connectionSocket.recv(2048)
                            email_length = int(decrypt_message(email_length, sym_key))
                            connectionSocket.send(encrypt_message("Ok", sym_key))
                                    
                            email = b''
                            #The while loop below receives our email in chunks until the length of the email variable is the same as the email_length
                            while len(email) != email_length:
                                data = connectionSocket.recv(4096)
                                email += data
                            
                            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                            
                            email = decrypt_message(email, sym_key)
                            email = email.replace("\033[1mTime and Date:\033[0m", f"\033[1mTime and Date:\033[0m {current_time}")
                            
                            client = splice_word(email, "From")
                            dest = splice_word(email, "To")
                            dest_list = dest.split(";")
                            length = splice_word(email, "Length")
                             
                            print(f"An email from {client} is sent to {dest} has content length of {length}")
                            title = splice_word(email, "Title")
                            #file_path = os.path.join(current_path, f'{dest_list[i]}', f'{client}_{title}.txt')    
                            current_path = os.getcwd()
                            index = 1
                            for i in range(len(dest_list)):
                                new_path = os.path.join(current_path, f'{dest_list[i]}')    
                                if not os.path.exists(new_path):
                                    os.makedirs(new_path)
                                client_file_path = os.path.join(new_path, f'{client}_{title}.txt')
                                #If the file exists within the folder, we add a number starting from 1 to the end of the file name.
                                #Checks files until file(index) is not found and adds it to the folder
                                if os.path.exists(client_file_path):
                                    while os.path.exists(os.path.join(new_path, f'{client}_{title}({index}).txt')):
                                        index += 1
                                    with open(os.path.join(new_path, f'{client}_{title}({str(index)}).txt'), "w") as file:
                                        file.write(email)
                                    break
                                else:
                                    with open(client_file_path, "w") as file:
                                        file.write(email)
 
                            
                        elif command == "2":
                            folder = username # folder for client
                            filelist = os.listdir(folder) # list of files in folder
                            list_dates, email_names, num_files, inbox_dict = inbox_data(filelist, folder) # function returns relevant lists, a counter and 
                                                                                                          # inbox data dictionary

                            inbox = "\nIndex\tFrom\t\tDateTime\t\t\t\tTitle\n"
                            print(list_dates)
                            print("before sorted dates")
                            sorted_dates = bubblesort(list_dates)
                            
                            num_files = len(sorted_dates)-1  # number of files to be compared
                            real_index = 1 # used for inbox index value
                            date_index = 0 # used for updating the current sorted date
                            
                            email_list.clear() #Clears email_list each time client calls "2"
                            while (num_files >= 0):
                                inbox_content = inbox_dict[folder] # parent dictionary {folder: {...}}
                                date_in_order = sorted_dates[date_index] # sorted stored date
                                
                                for emails in email_names:   
                                    email_data = inbox_content[emails] # for loop goes through each email
                                    email_date = email_data["date"]
                                    
                                    if (date_in_order == email_date):
                                        inbox += (f"{real_index}\t{email_data['sender']}\t\t"
                                                  f"{date_in_order}\t\t{email_data['title']}\n")
                                        #print(inbox)
                                        email_list.append(f"{email_data['sender']}:{email_data['title']}") #Appends sorted titles into email_list
                                        #print(email_list)
                                num_files -=  1 
                                real_index += 1 
                                date_index += 1 

                            inbox_length = str(len(inbox)) #obtain size
                            #print(inbox_length)
                            connectionSocket.send(encrypt_message(inbox_length, sym_key)) # send size
                            ok_recv = connectionSocket.recv(2048) # recieve OK
                            connectionSocket.send(encrypt_message(inbox, sym_key)) # send inbox string
     
                        elif command == "3":
                            index_request = "the server request email index\n"
                            connectionSocket.send(encrypt_message(index_request, sym_key))
                            
                            email_index = connectionSocket.recv(2048) #Recieve chosen index from client
                            email_index = decrypt_message(email_index, sym_key) 
                            
                            
                            temp = email_list[int(email_index)-1] #find chosen email title from email_list based on client chosen index-1
                            email_source =  temp[:temp.find(":")]
                            email_title = temp[temp.find(":")+1:]
                            
                            client_file_path = os.path.join(os.getcwd(), username, f"{email_source}_{email_title}.txt") #Path to client chosen file

                            with open(client_file_path, "r") as file:
                                chosen_email = file.read()
                            
                            encrypted_chosen_email = encrypt_message(chosen_email, sym_key) 
                            
                            connectionSocket.send(encrypt_message(len(encrypted_chosen_email), sym_key)) #Send the length of our encrypted email to use on client side
                            
                            ok = connectionSocket.recv(2048)
                            ok = decrypt_message(ok, sym_key)
                            
                            offset = 0
                            #The code below sends our email from above in chunks to better handle large file sizes
                            while offset < len(encrypted_chosen_email):
                                remaining = len(encrypted_chosen_email) - offset #Remaining size of email
                                chunk_size = min(4096, remaining) #chunk_size is the minimum of the buffer(4096) or remaining(Size of remaining email)
                                chunk = encrypted_chosen_email[offset:offset + chunk_size] #Takes characters from the offset to the offset and chunk_size
                                connectionSocket.send(chunk)
                                offset += chunk_size #Adds the chunk_size to offset


                connectionSocket.close()
                print(f"Terminating connection with {username}")

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
