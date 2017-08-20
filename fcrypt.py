# Author : Ashok Koduru
# Date   : 2nd Feb 2017
# Task   : Net Sec PS2

# System level imports
import os
import sys
import base64
import argparse

# Cryptography imports
from cryptography.exceptions import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization, padding as sympad
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Decryption Class
class Decrypt(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        dest_private_key_file = values[0]
        sender_public_key_file = values[1]
        input_file_ct = values[2]
        result_output_file = values[3]

        # Loading destination private key and sender public key
        try:
            with open(dest_private_key_file, 'rb') as key_file_pr:
                dest_private_key = serialization.load_der_private_key(key_file_pr.read(), password=None,
                                                                      backend=default_backend())
            with open(sender_public_key_file, 'rb') as key_file_pb:
                sender_public_key = serialization.load_der_public_key(key_file_pb.read(), backend=default_backend())
        except:
            print "Unexpected Error loading keys while decrypting"

        # Decrypted file
        result_out_file = open(result_output_file, 'w')

        # Reading Input cipher text file
        with open(input_file_ct, 'rb') as fl:
            cipher_text_content = fl.readlines()

        l1 = cipher_text_content[0]
        l2 = cipher_text_content[1]
        l3 = cipher_text_content[2]
        l4 = cipher_text_content[3]

        # Basic check on cipher text
        if len(l1) == 0 or len(l2) == 0 or len(l3) == 0 or len(l4) == 0:
            print "Encrypted file is not correct."
            sys.exit()

        # Separation of cipher text in to parts
        encrypted_session_key = base64.b64decode(l1)
        cipher_text = base64.b64decode(l2)
        signature_msg = base64.b64decode(l3)
        signature = base64.b64decode(l4)

        # Verifying the signature to check if it came from an authentic source
        try:
            verifier = sender_public_key.verifier(
                signature,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            verifier.update(signature_msg)
            verifier.verify()
        except InvalidSignature:
            print "The message failed the integrity test"
            sys.exit()

        # Obtaining the session key and iv for the main message
        key_iv_plain_text = dest_private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )

        # Separating the session key and iv
        session_key = key_iv_plain_text[:32]
        iv = key_iv_plain_text[32:]

        # Decrypt plain text using AES
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plain_text = decryptor.update(cipher_text) + decryptor.finalize()

        # Unpad the data
        unpadder = sympad.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(padded_plain_text)
        unpadded_data += unpadder.finalize()

        # Write in to output file
        result_out_file.write(unpadded_data)
        result_out_file.close()

        print "Decryption completed."


class Encrypt(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        dest_public_key_file = values[0]
        sender_private_key_file = values[1]
        input_file_pt = values[2]
        output_file = values[3]

        # Loading sender private key and destination public key
        try:
            with open(sender_private_key_file, 'rb') as key_file_pr:
                sender_private_key = serialization.load_der_private_key(key_file_pr.read(), password=None,
                                                                        backend=default_backend())
            with open(dest_public_key_file, 'rb') as key_file_pb:
                dest_public_key = serialization.load_der_public_key(key_file_pb.read(), backend=default_backend())
        except:
            print "Error loading keys while encrypting"

        # Reading input plain text file
        plain_text = open(input_file_pt, 'rb').read().rstrip('\n')

        # Encrypted output file
        out_file = open(output_file, 'w')

        # Create a random session key and initialization vector
        session_key = os.urandom(32)
        iv = os.urandom(16)

        # RSA on session key and iv
        key_iv_cipher = dest_public_key.encrypt(
            session_key+iv,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        out_file.write(base64.b64encode(key_iv_cipher)+'\n')

        # Padding the data to match the AES block size
        padder = sympad.PKCS7(128).padder()
        padded_data = padder.update(plain_text)
        padded_data += padder.finalize()

        # AES on the input message
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        out_file.write(base64.b64encode(ct)+'\n')

        # Signing the message with a HASH Algorithm for integrity
        signature_msg = os.urandom(32)
        signer = sender_private_key.signer(
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        signer.update(signature_msg)
        signature = signer.finalize()

        # Writing the signature and digest in to the file
        out_file.write(base64.b64encode(signature_msg) + '\n')
        out_file.write(base64.b64encode(signature) + '\n')

        out_file.close()

        print "Encryption Completed"
        

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--decrypt",
                    nargs=4,
                    action=Decrypt,
                    metavar=('destination_private_key_filename',
                             'sender_public_key_filename',
                             'ciphertext_file',
                             'output_plaintext_file'),
                    help="Securely decrypt the given file")
parser.add_argument("-e", "--encrypt",
                    nargs=4,
                    action=Encrypt,
                    metavar=('destination_public_key_filename',
                             'sender_private_key_filename',
                             'input_plaintext_file',
                             'ciphertext_file'),
                    help="Securely Encrypt the given file")


args = parser.parse_args()
