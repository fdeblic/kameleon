# kameleon
The Kameleon script encrypts files into *.kam ones. The encrypted data is obtained thanks to a XOR transformation between a chosen hexadecimal key and the original data.

The script need two arguments : the file (-f or --file) and the hexadecimal key (-k or --key). If the input file is encrypted (*.kam), it will be decrypted and the .kam extension will be removed.
