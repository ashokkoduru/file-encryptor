#!/bin/bash

# Simple test for fcrypt (CS 4740/6740: Network Security)
# Amirali Sanatinia (amirali@ccs.neu.edu)

#python fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file
#python fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file

if ! diff -q a.txt res_out.txt > /dev/null ; then
  echo "FAIL"
  else echo "PASS!"
fi


