package com.endecode;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class AES extends EnDeCode{

  private static final int IVSIZE = 16;//the size of the IV generated
  private static MessageDigest MD = null;//holds the message digest that will be used for the hash.
  private static int MDLENGTH;//holds the length of the message digest.
  private Cipher cipher;
  private boolean checkHash = true;

  public AES(String password)
  throws 
  NoSuchAlgorithmException,//thrown if the transform is not valid.
  NoSuchPaddingException,//thrown if the password can not be used
  InvalidKeySpecException{//thrown if the key cant be used.
    super(password);
    if(MD == null){
      MD = MessageDigest.getInstance("MD5");
      MDLENGTH = MD.getDigestLength();
    }
    this.cipher = Cipher.getInstance(TRANSFORM);
  }

  /**
   * This is the methrd used to encrypt and decrypt data.
   * @param cipherMode weather the data given is encrypted or decrypted.
   * @param data the data that will be encrypted or decrypted.
   * @param IV the IV used in the encrpytion or decrpytion.
   * @return the encrypted or decrypted byte[].
   */
  private byte[] apply(int cipherMode, byte[] data, byte[] IV) 
  throws 
  InvalidKeyException,//thrown if the key is invalid.
  InvalidAlgorithmParameterException,//thrown if any of the inputs are inavalid
  IllegalBlockSizeException,//thrown if the data can not be decrypted.
  BadPaddingException{//thrown if the data can not be encrypted.
    IvParameterSpec ivspec = new IvParameterSpec(IV);//gets the IV paramater.
    cipher.init(cipherMode, super.getPassword(), ivspec);//loads in the cipher with the mode key and iv.
    data = cipher.doFinal(data);//encrypts the bytes or decrypts depending.
    return data;//reurns the final byte array.
  }

  /**
   * encrypt a byte[].
   * @param data the byte[] that you want to encrypt.
   * @return the encrypted byte[].
   */
  public byte[] encrypt(byte[] data)
  throws
  InvalidAlgorithmParameterException,//throws if one of the parameters are invalid shoud not be thrown
  BadPaddingException,//thrown if the data can not be encrypted.
  InvalidKeyException,//thrown if the key used is invalid.
  IllegalBlockSizeException{//thrown if the data can not be encrypted
    byte[] IV = getNewIV();//loads in a new IV for the encryption
    data = addHash(data);//adds the hash to the unencrypted data.
    data = apply(Cipher.ENCRYPT_MODE,data,IV);//appliyes the encryption to the data with the new IV
    data = addIV(data,IV);//adds the IV to the tail of the data.
    data = super.addEN(data);//adds the en byte[] to the end of the data
    return data;//will return the encrypted data.
  }

  /**
   * encrypt a string.
   * @param data the string that you want to encrypt.
   * @return a Base64 encoded string that has been encrypted.
   */
  public String encrypt(String data)
  throws 
  InvalidAlgorithmParameterException,//throws if one of the parameters are invalid shoud not be thrown
  BadPaddingException,//thrown if the data can not be encrypted.
  InvalidKeyException,//thrown if the key used is invalid.
  IllegalBlockSizeException{//thrown if the data can not be encrypted
    byte[] byteData = encrypt(data.getBytes());//encrypts the Strings bytes
    String encodedString = Base64.getEncoder().encodeToString(byteData);//encodes the string to base64.
    return encodedString;//returns the new encoded string
  }

  /**
   * Decrypt a string that was encrypted using this libary.
   * @param data the encrypted string.
   * @return the original decrypted string.
   */
  public String decrypt(String data)
  throws
  IllegalBlockSizeException,//thrown if the data was not encrypted
  InvalidAlgorithmParameterException,//thrown when the hash dose not match
  InvalidKeyException,//thrown if the key is not valid will require loading again with new password.
  BadPaddingException{//thrown if the bytes given were not encrypted.
    byte[] byteData = decrypt(Base64.getDecoder().decode(data));//decodes the string into bytes from base64.
    return new String(byteData);//returns the decrypted string.
  }

  /**
   * Decrypt an encrypted byte[] that used this libary.
   * @param data the encrypted data that you want to decrypt.
   * @return the decrypted data.
   */
  public byte[] decrypt(byte[] data)
  throws
  IllegalBlockSizeException,//thrown if the data was not encrypted
  InvalidAlgorithmParameterException,//thrown when the hash dose not match
  InvalidKeyException,//thrown if the key used is not valid will require loading this again with new password.
  BadPaddingException{//thrown if the bytes given were not encrypted in the first place.
    data = removeEN(data);//remove the encryption byte[] from the data.
    byte[] IV = getIV(data);//get the IV used for encryption.
    data = removeIV(data);//remove the IV from the data.
    data = apply(Cipher.DECRYPT_MODE,data,IV);//decrypt the data and save it to the data.
    data = removeHash(data);//remove the hash from the data this also checks the hash.
    return data;//will be the decrypted data.
  }


  /**
   * remove the IV that was used for encrypteion.
   * @param data the data with the IV on the end.
   * @return returns the data without the IV on the end.
   */
  private byte[] removeIV(byte[] data){
    byte[] tmp = data;//stores the data in a tmp[]
    data = new byte[tmp.length-IVSIZE];//create a new array for the data smaller that the IV size.
    System.arraycopy(tmp, 0, data, 0, data.length);//copy the data without the IV into the data[]
    return data;//return the data without the IV.
  }

  /**
   * gets the IV that is contained on the end of the IV array.
   * @param data the data with the IV on the end.
   * @return the IV that is contained on the end of the data.
   */
  private byte[] getIV(byte[] data){
    byte[] IV = new byte[IVSIZE];//create a new array that is the size of the IV used.
    System.arraycopy(data,data.length-IVSIZE,IV,0,IVSIZE);//copy the IV data over to the array
    return IV;//return the new IV.
  }

  /**
   * generates a new random IV to use for encryption.
   * @return a new random IV for the data.
   */
  private byte[] getNewIV(){
    SecureRandom srand = new SecureRandom();//get a secure random.
    byte[] IV = new byte[IVSIZE];//create a new IV of the IV size.
    srand.nextBytes(IV);//get random number of bytes into the IV[]
    return IV;//return the new IV to use with encryption.
  }

  /**
   * adds the IV to the end of the data that has been encrypted.
   * @param data the encrypted data.
   * @param IV the IV that was used to encrypt the data.
   * @return the byte array with the IV  on the end of the data.
   */
  private byte[] addIV(byte[] data, byte[] IV){
    byte[] tmp = data;//create a tmp array to hold the data.
    data = new byte[tmp.length+IV.length];//create a new data array with the length of the IV.
    System.arraycopy(tmp,0,data,0,tmp.length);//copy the original data into the array.
    System.arraycopy(IV,0,data,tmp.length,IV.length);//copy the IV to the end of the data.
    return data;//return the data with the IV on the end.
  }


  /**
   * this remove and validates the hash that is contained on the end of the data byte[].
   * @param data the data with the hash array on the end of the data.
   * @return a byte[] that dose not contain the hash on the end.
   */
  private byte[] removeHash(byte[] data) 
  throws 
  InvalidAlgorithmParameterException{//throws when the hash of the data dose not match
    byte[] tmp = data;//create a tmp array to hold the data.
    byte[] hash = getHash(tmp);//get the hash of the tmp data.
    data = new byte[tmp.length-hash.length];//create new array smaller that the hash size.
    System.arraycopy(tmp,0,data,0,data.length);//copy the original data into the new array.
    if(checkHash){
      if(!validateHash(data,hash)) throw new InvalidAlgorithmParameterException("Invalid Hash");//check the two hashes and throw exception if invalid.
    }
    checkHash = true;
    return data;//return the data[] without the hash.
  }

  /**
   * When called the next time that you decrypt the hash will be skiped, after the next decrypt it will then check the hash afterwareds.
   */
  public void skipHash(){
    checkHash = false;//sets it so that the next check will skip checking the hash
  }

  /**
   * adds a hash of the data onto the end of the data.
   * @param data the data that the hash is generated on and added onto the end of.
   * @return a byte[] with the data and the hash on the end.
   */
  private byte[] addHash(byte[] data){
    byte[] hash = genHash(data);//generates a new hash for the data.
    byte[] tmp = data;//create a tmp[] for the data
    data = new byte[tmp.length+hash.length];//create a new array with the hash length.
    System.arraycopy(tmp,0,data,0,tmp.length);//copy the original data into the array.
    System.arraycopy(hash,0,data,tmp.length,hash.length);//copy the new hash into the array.
    return data;//return the data with the hash on the end.
  }

  /**
   * gets the hash of of the end of the data array.
   * @param data the byte[] with the hash on the end.
   * @return the byte array that contains the hash in the data.
   */
  private byte[] getHash(byte[] data){
    byte[] hash = new byte[MDLENGTH];//create a new array of the hash length
    System.arraycopy(data,data.length-MDLENGTH,hash,0,MDLENGTH);//copy the hash from data into the new hash[]
    return hash;//return the hash retreved from the data.
  }
  
  /**
   * generates a hash on the data given.
   * @param data the data that the hash will be generated on.
   * @return a hash byte[] generated using the data.
   */
  private byte[] genHash(byte[] data){
    MD.update(data);//add the data to the message digest
    byte[] hash = MD.digest();//generate the hash using the data.
    return hash;//return the newly generated hash.
  }

  /**
   * validate the hash given the data without the hash and the hash on the end of the data.
   * @param data the data that the hash will be generated using.
   * @param hash the has that was removed from the data.
   * @return weather the hash could be validated.
   */
  private boolean validateHash(byte[] data, byte[] hash){
    byte[] newHash = genHash(data);//generate the hash using the current data.
    for(int i = 0; i < hash.length; i++){//loop through the lenght of the hash and validate.
      if(hash[i] != newHash[i]) return false;//if the hash bytes dont match return false.
    }
    return true;//if the end of the methrod is reached return true.
  }
}
