# This is the enhanced with additional security server side of the SMTP program
# Conlan Myers - 3110785
# Moses Lemma - 3108513
# Rajiv Naidu - 3060912
import json
import socket
import sys, glob, datetime
import os
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pss
from Crypto.Hash import SHA256, HMAC
from Crypto.Util import Counter

# Use this to generate a sym_key of size 32(256bits)
# Can change size to change the size of the key
def generate_sym_key(size=32):
    return get_random_bytes(size)


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

def decrypt_message_ctr(encrypted_message, sym_key, nonce):
    ctr = Counter.new(64, prefix=nonce, little_endian=True, allow_wraparound=True)
    cipher_message = AES.new(sym_key, AES.MODE_CTR, counter=ctr)
    decrypted_message = cipher_message.decrypt(encrypted_message)
    unpadded_message = unpad(decrypted_message, 16)
    message = unpadded_message.decode('utf-8')
    return message

def validate_mac(message, mac, sym_key):
    with open("server_private.pem", "rb") as file:
        server_priv = file.read()
    with open("client1_public.pem", "rb") as file:
        client_pub = file.read()
    h = HMAC.new(sym_key, message.encode(), digestmod=SHA256)
    print(h.hexdigest(), "MAC: Server Side")
    try:
        h.hexverify(mac)
        return "Valid Message"
    except ValueError:
        return "Invalid Message"
    

# Gives you a string representation of the encrypted sym key
def print_encrypted_sym(encrypted_sym_key):
    encrypted_sym_key_hex = ''.join([format(byte, '02x') for byte in encrypted_sym_key])
    print('SYMMETRIC KEY (HEX): ', encrypted_sym_key_hex)
    return


# Made solely for finding our target words such as 'From' and 'To' from our email
def splice_word(string, target):
    start = string.find(target)
    middle = string.find(":", start)
    middle2 = string.find("m", middle)
    end = string.find("\n", middle2)

    return string[middle2 + 1:end].strip()


def valid_timestamp(timestamp, valid_time=5):
    current = datetime.now()
    timestamp_datetime = datetime.fromtimestamp(timestamp)
    diff = current - timestamp_datetime
    if diff <= timedelta(seconds=valid_time):
        return True
    else:
        return False
    
    

    

def initial_connection_protocol(connectionSocket):
    # This is the server client communication protocol for when the initial connection

    # Creates the private key and cipher from the server private key
    server_pri = RSA.importKey(import_private_key())
    private_rsa_server = PKCS1_OAEP.new(server_pri)

    # Receives the signature
    signature = connectionSocket.recv(2048)

    # Receives the username
    encrypted = connectionSocket.recv(2048)
    username = private_rsa_server.decrypt(encrypted).decode("ascii")

    # Receives the Password
    encrypted = connectionSocket.recv(2048)
    password = private_rsa_server.decrypt(encrypted).decode("ascii")

    # Gets the public key and makes a hash of the username to verify the received signature
    client_pub = RSA.importKey(import_public_key(username))
    hash_sig = SHA256.new(username.encode("ascii"))
    print("Hash: ", hash_sig.digest())
    verification = pss.new(client_pub)
    try:
        verification.verify(hash_sig, signature)

    except ValueError:
        connectionSocket.send("Incorrect Digital Signature".encode("ascii"))
        print(f"The received Client Digital Signature from: {username} is invalid (Connection Terminated)")
        return False, None, username

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
        # Creates public Cipher from the client public key
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
        return False, None, username


def substring(string, delimiter):
    return string.partition(delimiter)[2]

def empty_folder_check(path):
    files = glob.glob(path + "/*")
    return not bool(files)

# Bubble sort for dates
def bubblesort(elements):
    # Added to prevent issues when the length of elements is 1 (otherwise
    # returns 1) - ConlanS
    if len(elements) == 1:
        return elements
    swapped = False
    for n in range(len(elements) - 1, 0, -1):
        for i in range(n):
            # datetime_obj1 = datetime.strptime(date_str1, '%Y-%m-%d %H:%M:%S')
            if datetime.strptime(elements[i], '%Y-%m-%d %H:%M:%S.%f') > datetime.strptime(elements[i + 1],
                                                                                          '%Y-%m-%d %H:%M:%S.%f'):
                swapped = True
                elements[i], elements[i + 1] = elements[i + 1], elements[i]
        if not swapped:
            return elements
        return elements


def inbox_data(filelist, folder):
    inbox_dict = {}  # dictionary for inbox data
    inbox_dict[folder] = {}  # Nest inbox_dictionary

    list_dates = []  # list to store dates individually to be sorted
    email_names = []  # list to store email names
    num_files = 0  # counter for # of emails

    for file in filelist:
        path = os.path.join(folder, file)  # path to each file in the directory ex. client1/client1_Greetings.txt
        email_names.append(file)

        # OBTAINING DATA FROM FILES
        with open(path, "r") as email_file:
            lines = email_file.readlines()  # stores every line in file
            # reading each line in the email
            for line in lines:
                if (line.startswith("[1mFrom:[0m ")):
                    # delimits the line and saves name of SENDER
                    client_sender = substring(line, "[1mFrom:[0m ").strip("\n")

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
            num_files += 1

    return list_dates, email_names, num_files, inbox_dict


def create_inbox(inbox, inbox_dict, email_list, email_names, num_files, sorted_dates, folder):
    real_index = 1  # used for inbox index value
    date_index = 0  # used for updating the current sorted date

    while (num_files >= 0):
        inbox_content = inbox_dict[folder]  # parent dictionary {folder: {...}}
        date_in_order = sorted_dates[date_index]  # sorted stored date

        for emails in email_names:
            email_data = inbox_content[emails]  # for loop goes through each email
            email_date = email_data["date"]

            if (date_in_order == email_date):
                inbox += (f"{real_index:<8}{email_data['sender']:<12}"
                          f"{date_in_order:<31}{email_data['title']}\n")
                email_list.append(
                    f"{email_data['sender']}:{email_data['title']}")  # Appends sorted titles into email_list

        num_files -= 1
        real_index += 1
        date_index += 1

    return inbox, email_list


def server():
    # Server port
    serverPort = 13000

    # Create server socket that uses IPv4 and TCP protocols
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in server socket creation:', e)
        sys.exit(1)

    # Associate 13000 port number to the server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:', e)
        sys.exit(1)

    print('The server is ready to accept connections')

    # The server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(5)

    email_list = []  # Email titles in sorted order

    while 1:
        try:
            # Server accepts client connection
            connectionSocket, addr = serverSocket.accept()
            pid = os.fork()
            accepted_clients = ["client1","client2","client3","client4","client5"]
            # If it is a client process
            if pid == 0:
                serverSocket.close()

                accepted_connection, sym_key, username = initial_connection_protocol(connectionSocket)
                if accepted_connection:
                    # noinspection PyTypeChecker
                    sym_cipher = AES.new(sym_key, AES.MODE_ECB)

                    command = "0"
                    #seq = None
                    nonce_set = set()
                    inbox_printed = 0 # num of times inbox has been generated
                    # Loops until the command is 4 (exit)
                    increment = int(decrypt_message(connectionSocket.recv(2048), sym_key))
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

                        # Sending email
                        if command == "1":
                            current_path = os.getcwd()
                            message = "Send this email\n"
                            connectionSocket.send(encrypt_message(message, sym_key))

                            email_length = connectionSocket.recv(2048)
                            email_length = decrypt_message(email_length, sym_key)
                            if (email_length == "Ok"):
                                continue
                            email_length = int(email_length)
                            connectionSocket.send(encrypt_message("Ok", sym_key))

                            json_data = b''
                            # The while loop below receives our email in chunks until the length of the email variable is the same as the email_length
                            while len(json_data) < email_length:
                                data = connectionSocket.recv(4096)
                                json_data += data
                            
                            #Nonce was prepending during client encryption so we split it from the data
                            nonce = json_data[:8]
                            print(nonce.hex(), "Nonce: Server Side")
                            
                            #Check to see if nonce is in a set, if it is than it might be a possible attack
                            #Nonces should be unique
                            if nonce in nonce_set:
                                nonce_response = "Repeated Nonce. Rejecting Message."
                                connectionSocket.send(encrypt_message(nonce_response, sym_key))
                                continue
                            else:
                                connectionSocket.send(encrypt_message("Ok", sym_key))
                                #Add nonce to set if not in set
                                nonce_set.add(nonce)
                            ok = decrypt_message(connectionSocket.recv(2048), sym_key)
                            
                            #Save the rest of the encrypted message data in email_data
                            email_data = json_data[8:]
                            #Decrypt with CTR mode
                            email_data = decrypt_message_ctr(email_data, sym_key, nonce)
                            #Use loads to get back into key accessible format
                            email_data = json.loads(email_data)
                            mac = email_data['mac']
                            #We delete the MAC from the payload so we can generate another MAC
                            #In the same conditions as the client side
                            #This will help us validate the MAC
                            if 'mac' in email_data:
                                del email_data['mac']
                            #Re-Serialize the data so we can use it in validating the mac
                            email_data = json.dumps(email_data)
                            
                            #Validate mac compares the client mac to our newly generated mac
                            if validate_mac(email_data, mac, sym_key) == "Invalid Message":
                                mac_response = "Invalid MAC: Rejcting Message."
                                connectionSocket.send(encrypt_message(mac_response, sym_key))
                                continue
                            else:
                                connectionSocket.send(encrypt_message("Ok",sym_key))    
                            ok = decrypt_message(connectionSocket.recv(2048), sym_key)

                            #Use loads to get back into key accessible format
                            email_data = json.loads(email_data)
                            email = email_data['message']
                            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                            #Add the current time to our email
                            email = email.replace("\033[1mTime and Date:\033[0m",f"\033[1mTime and Date:\033[0m {current_time}")
                            #Splice_word find the relevant information and saves it into a relvant variable
                            
                            client = splice_word(email, "From")
                            dest = splice_word(email, "To")
                            #Split destination clients up by the separator ;
                            dest_list = dest.split(";")
                            length = splice_word(email, "Length")
                            title = splice_word(email, "Title")
                            #Valid timestamp simply compares current time with the timestamp, if the difference is more
                            #Than the timedelta(valid_time=x) than it is invalid and outdated
                            if valid_timestamp(email_data['timestamp'], 5) == False:
                                timestamp_response = "Timestamp outdated. Please resubmit your request."
                                connectionSocket.send(encrypt_message(timestamp_response, sym_key))
                                continue
                            else:
                                connectionSocket.send(encrypt_message("Ok",sym_key))    
                            ok = decrypt_message(connectionSocket.recv(2048), sym_key)
                            
                            #We separate the valid and invalid clients into lists
                            #Valid clients are client1,client2,client3,client4 and client5
                            invalid_clients = []
                            valid_clients = []
                            for item in dest_list:
                                if item not in accepted_clients:
                                    invalid_clients.append(item)
                                else:
                                    valid_clients.append(item)
                            if len(invalid_clients) != 0:
                                #For formatting we join the list into a string separated by a ,
                                delimited_string = ", ".join(invalid_clients)
                                invalid_clients = "Email was not sent to " + delimited_string + ". Invalid recipient(s)"
                                connectionSocket.send(encrypt_message(invalid_clients, sym_key))
                            else:
                                connectionSocket.send(encrypt_message("Ok", sym_key))
                            ok = decrypt_message(connectionSocket.recv(2048), sym_key)
                            
                            #Make a new dest variable filled only with valid clients
                            dest = ";".join(valid_clients)

                            print(f"An email from {client} is sent to {dest} has content length of {length}")
    
                            index = 1
                            #We go through the list of valid clients
                            for i in range(len(valid_clients)):
                                new_path = os.path.join(current_path, f'{valid_clients[i]}')
                                #Make a new directory if it doesnt exist, for the client
                                if not os.path.exists(new_path):
                                    os.makedirs(new_path)
                                client_file_path = os.path.join(new_path, f'{client}_{title}.txt')
                                # If the file exists within the folder, we add a number starting from 1 to the end of the file name.
                                # Checks files until file(index) is not found and adds it to the folder
                                if os.path.exists(client_file_path):
                                    while os.path.exists(os.path.join(new_path, f'{client}_{title}({index}).txt')):
                                        index += 1
                                    #If there are multiple of the same title, we just add an index that increments
                                    #For each title that is found that is the same
                                    with open(os.path.join(new_path, f'{client}_{title}({str(index)}).txt'),"w") as file:
                                        new_title = title + f"({str(index)})"
                                        email = email.replace(f"\033[1m\033[1mTitle:\033[0m {title}\n", f"\033[1m\033[1mTitle:\033[0m {new_title}\n")
                                        file.write(email)
                                    break
                                else:
                                    with open(client_file_path, "w") as file:
                                        file.write(email)

                        # This protocol will generate a dictionary for email data for either 
                        # protocol's 2 or 3 but only sends over the inbox if the user chooses protocol 2
                        if command == "2" or command == "3" and inbox_printed == 0:
                            current_path = os.getcwd()
                            new_path = os.path.join(current_path, f'{username}')    
                            if not os.path.exists(new_path):
                                    os.makedirs(new_path)
                    
                            inbox = "Index   From        DateTime                       Title\n"
                            folder = username # folder for client
                            filelist = os.listdir(folder) # list of files in folder


                            # The inbox is only generated if there is a least one email
                            # in the client's folder
                            if len(filelist) > 0:
                                list_dates, email_names, num_files, inbox_dict = inbox_data(filelist, folder) # function returns relevant lists, a counter and                                                                           # inbox data dictionary
                                sorted_dates = bubblesort(list_dates) # sorts list of dates
                                num_files = len(sorted_dates)-1  # number of files to be compared
                                email_list.clear() #Clears email_list each time client calls "2" or "3"

                                # create_inbox() creates the returns the inbox string and updates the email_list
                                inbox, email_list = create_inbox(inbox, inbox_dict, email_list, email_names, num_files, sorted_dates, folder)
                            
                                # if the client entered a 2 the inbox is sent to the client, 
                                # otherwise only the inbox dictionary and email_list is created/updated
          
                            inbox_length = str(len(inbox)) #obtain size
                            connectionSocket.send(encrypt_message(inbox_length, sym_key)) # send size
                            ok_recv = connectionSocket.recv(2048) # recieve OK
                            connectionSocket.send(encrypt_message(inbox, sym_key)) # send inbox string
                            inbox_printed += 1 # increment to establish that inbox was printed once
                        # Sending over email contents
                        if command == "3":
                            index_request = "the server request email index\n"
                            connectionSocket.send(encrypt_message(index_request, sym_key))

                            email_index = connectionSocket.recv(2048)  # Recieve chosen index from client
                            email_index = decrypt_message(email_index, sym_key)
                            
                            if empty_folder_check(username):
                                empty_folder_reponse = "Your inbox is currently empty.\n"
                                connectionSocket.send(encrypt_message(empty_folder_reponse,sym_key))
                                ok = decrypt_message(connectionSocket.recv(2048), sym_key)
                                continue
                            else:
                                connectionSocket.send(encrypt_message("Ok",sym_key))
                            ok = decrypt_message(connectionSocket.recv(2048), sym_key)
                            
                            # Checks to see if index is within the len of the email_list and 0
                            while True:
                                if int(email_index) <= 0 or int(email_index) > len(email_list):
                                    connectionSocket.send(encrypt_message("Index out of range. Please enter another index: ", sym_key))
                                    email_index = connectionSocket.recv(2048)
                                    email_index = decrypt_message(email_index, sym_key)
                                else:
                                    connectionSocket.send(encrypt_message("Ok", sym_key))
                                    break
                            ok = decrypt_message(connectionSocket.recv(2048), sym_key)
                            temp = email_list[int(email_index) - 1]  # find chosen email title from email_list based on client chosen index-1
                            email_source = temp[:temp.find(":")]
                            email_title = temp[temp.find(":") + 1:]

                            client_file_path = os.path.join(os.getcwd(), username,f"{email_source}_{email_title}.txt")  # Path to client chosen file
                            with open(client_file_path, "r") as file:
                                chosen_email = file.read()

                            encrypted_chosen_email = encrypt_message(chosen_email, sym_key)

                            connectionSocket.send(encrypt_message(len(encrypted_chosen_email),sym_key))  # Send the length of our encrypted email to use on client side

                            ok = connectionSocket.recv(2048)
                            ok = decrypt_message(ok, sym_key)

                            offset = 0
                            # The code below sends our email from above in chunks to better handle large file sizes
                            while offset < len(encrypted_chosen_email):
                                remaining = len(encrypted_chosen_email) - offset  # Remaining size of email
                                chunk_size = min(4096,
                                remaining)  # chunk_size is the minimum of the buffer(4096) or remaining(Size of remaining email)
                                chunk = encrypted_chosen_email[
                                offset:offset + chunk_size]  # Takes characters from the offset to the offset and chunk_size
                                connectionSocket.send(chunk)
                                offset += chunk_size  # Adds the chunk_size to offset
                            ok = decrypt_message(connectionSocket.recv(2048), sym_key)
                else:
                    # This prevents a duplicate print to the server
                    connectionSocket.close()
                    return
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
