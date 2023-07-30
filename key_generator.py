# This is the RSA key generator functions for the SMTP program
# Conlan Myers - 3110785
# Moses Lemma - 3108513
# Rajiv Naidu - 3060912
from Crypto.PublicKey import RSA

# Use this to generate RSA public and private keys
def generate_keys():
    private_key = RSA.generate(2048)
    public_key = private_key.public_key()
    return private_key, public_key

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