# EnDeCode
Just a small libary using java encryption

This is a libary that will encrypt both byte[] arrays and Strings I am using Strings to encrypt the file name.
the string and file encryption is split into two classes

  StringEncryptDecrypt
  FileEncryptDecrypt

from FileEncryptDecrypt class you are also able to do string encryption there is no need to call StringEncryptDecrypt if you are using FileEncryptDecrypt.
The basic use of these classes is to get an instance of them using the getInstance() methord. you are required to have a string password that is going to be the
password used for both encryption and decryption.

  FileEncryptDecrypt fileEncryptDecrypt = FileEncryptDecrypt.getInstance(password);
  StringEncryptDecrypt stringEncryptDecrypt = StringEncryptDecrypt.getInstance(password);

if required you are able to change the password used by calling the changePassword() methord and providing it with the new password to be used.

  fileEncryptDecrypt.changePassword(password);
  stringEncryptDecrypt.changePassword(password);

to encrypt and decrypt a byte array or a string you just need to call the Encrypt() and Decrypt() methrods if you are using FileEncryptDecrypt you use the same methords for
encrypting a string as well just pass a string as the parameter insted of a byte array.

  fileEncryptDecrypt.Encrypt(byte[] or String);
  fileEncryptDecrypt.Decrypt(byte[] or String);
