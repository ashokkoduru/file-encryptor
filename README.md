The fcrypt.py is an python executable file which contains methods for both encryption and decryption

They can be run in the following way
1. For encrypting
python fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file output_ciphertext_file

2. For Decrypting
python fcrypt.py -d destination_private_key_filename sender_public_key_filename input_ciphertext_file output_plaintext_file


This code makes use of the crptography library of python 2.7
To run this code create a vitualenv of python2.7(optional) and install using the following command

pip install cryptography
