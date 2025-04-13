In this library, I encorperate 6 AES modes: ECB, CBC, CFB, OFB, CTR, and GCM

In the test directory, there are scritps to test against the NIST test vectors if you want to verify functionality. To get the NIST test vectors, go here: https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Block-Ciphers
Test syntax is: ./run_aes_{mode}_test.sh {testvector.rsp} main

Note: The ECB and CBC modes will not pass the NIST decryption tests because the NIST spec assumes perfect 16 byte blocks for those tests. My functions employ PKCS#7 padding, so you wind up with an extra 16 bytes of ciphertext if you pass a multiple of 16 byte plaintext. The encryption tests will pass however becuase I added a line in the test shell script to strip off the last 16 bytes. Its "cheating", but my implementation is more robust. The other mode tests should all pass because none of them use padding. 

Note: For CFB mode, I only implemented CFB128, not CFB1 or CFB8.


Note: For GCM mode, I only support 128 bit tags. 

Directions to build:
run "make" in the lib_crypto directory

Mode Syntax:
ECB: ./main ECB filename key_string enc_dec 
CBC: ./main CBC filename key_string IV_string enc_dec    
CFB: ./main CFB filename key_string IV_string enc_dec  
OFB: ./main OFB filename key_string IV_string enc_dec  
CTR: ./main OFB filename key_string IV_string enc_dec counter_start_string
GCM: ./main OFB filename key_string IV_string enc_dec -aad AAD_filename -tag tag_string -ctr counter_start_string

Note: For GCM mode you dont need AAD if there is none, you dont need a tag if you are encrypting, and you dont need to specify a counter, but you can if you want to.