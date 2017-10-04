# EnDeCode
Just a small libary using java encryption

This is a libary that will encrypt both byte[] arrays and Strings I am using Strings to encrypt the file name.

This class is very simple, to start you need to import the encryption libary AES like such

  com.endecode.AES;

There is other libarys such as RSAS and RSA but these are not full implemented and tested yet so best to avoid using them.

To start using the libary you need data to encrypte at the moment it supports byte arrays and strings, your string will be
returned using Base64 encoding. to start encrypting data you need to create a new instance of the AES class and pass in a 
password that will be used NOTE this password will be use for all encrypts and decrypts with no option at the moment to change it
if you want to change the password generate a new instance of the class.

  AES aes = new AES(<password>);

To then start encrypting data use the encrypt function this is the same for both byte arrays and strings the only diffrence is the 
format of the data you pass in strings will be encoded using base64 so if you want to use a diffrent encoding pass the string in as a
byte array just make sure you do the same when decrypting the string as well.

  aes.encrypt(new byte[20]); //the byte array to encrypt
  ase.encrypt("String to encrypt"); //the string the encrypt

To decrpyt the data it is just a matter of calling the decrypt function this is the same as above supports strings and byte array using the 
same name

  aes.decrypt(new byte[10]); //the byte array to decrypt
  aes.decrypt("String to decrpyt"); //the string to decrypt

If the data can not be verified with the EN byte array then it will through an IllegalBlockSizeException indecating that this data is either not encrypted using this 
libary or the data is not encrypted witch is true is up to you but either way the data can not be decrypted if you want to verify this before hand and get a boolean insted
of an exception you can use the isEncrypted() function to get this information this is the same as the ones above suppoting both byte arrays and Strings.

  aes.isEncrypted(new byte[10]); //the byte array to check
  aes.isEncrypted("String to check"); //the string to check