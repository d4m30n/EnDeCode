# EnDeCode
Just a small libary using java encryption

This is a libary that will encrypt both byte[] arrays and Strings I am using Strings to encrypt the file name.
the string and file encryption is split into two classes

  StringEncryptDecrypt
  FileEncryptDecrypt

from FileEncryptDecrypt class you are also able to do string encryption there is no need to call StringEncryptDecrypt if you are using FileEncryptDecrypt.
The basic use of these classes is to get an instance of them using the getInstance() methord. you are required to have a string password that is going to be the
password used for both encryption and decryption. and a boolean that indecates that you want to generate new public and private keys if left blank it will be assumed that
you do not want to generate a new public and private key warning this will overrite your original keys and for all files signed the signiture will now be invalid.

  FileEncryptDecrypt fileEncryptDecrypt = FileEncryptDecrypt.getInstance(password);
  StringEncryptDecrypt stringEncryptDecrypt = StringEncryptDecrypt.getInstance(password);

to encrypt and decrypt a byte array or a string you just need to call the Encrypt() and Decrypt() methrods if you are using FileEncryptDecrypt you use the same methords for
encrypting a string as well just pass a string as the parameter insted of a byte array.

  fileEncryptDecrypt.Encrypt(byte[] or String);
  fileEncryptDecrypt.Decrypt(byte[] or String);

when decrypting anything be it a file or a string there is always going to be a signiture check by default however this signiture check can be avoided
by adding a boolean as one of the parameters when decrypting this is not recomended as the invalid signiture is likly due to a modified file from the one original Encrypted
but i can also be a result of lost original RSA keys, to force decryption use this methrod below

  fileEncryptDecrypt.Decrypt(byte[] or String, false);

to achieve signing files and strings the program will generate both a public and private key that is use to generate a signiture. the private key is encrypted and saved to the file
system when it is generated and the password used to decrypt it is the one given in the getInstance(). you will be unable to encrypt or decrypt anything if you forget the password and
will be forced to regenerate the keys again like such.

  FileEncryptDecrypt fileEncryptDecrypt = FileEncryptDecrypt.getInstance(password, true);

there is also a methrod called isEncrypted() this is what it say when called it will return a boolean indecating wether or not the file is valid and was encrypted by this program.
this is called by default when decrypting but can be nice to know before hand as all it will do is return the same byte[] giving no indecation that isEncrypted was false.

FUTURE
in the future i plan on adding a recovary option where if you remember the password the file can be recoved by providing this password but note that this option will not be able to validate
any signiture on the file.
