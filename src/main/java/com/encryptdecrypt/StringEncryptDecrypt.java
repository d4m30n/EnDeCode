package com.encryptdecrypt;

import java.io.IOException;
import java.util.Base64;
import java.security.SecureRandom;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;


import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKey;
import java.security.spec.InvalidKeySpecException;


import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;

public class StringEncryptDecrypt extends EncryptDecrypt{
  protected StringEncryptDecrypt(){}
  private static StringEncryptDecrypt instance = null;

  public static StringEncryptDecrypt getInstance(String password) throws Exception{
    return getInstance(password,false);
  }

  public static StringEncryptDecrypt getInstance(String password, boolean genNewKeys) throws Exception{
    if(instance == null){
      instance = new StringEncryptDecrypt();
    }
    if(CodeInstance == null || genNewKeys){
      CodeInstance = EnDeCode.getInstance(password);
      CodeInstance.loadKeys(password, genNewKeys);
    }
    return (StringEncryptDecrypt) instance;
  }

  public boolean isEncrypted(String oString){
    try{//catch all erros that can occure.
      byte[] oStringBytes = Base64.getDecoder().decode(oString);//decode the given string.
      int lenCheck = oStringBytes.length-EN.length;//checks the byte length is not going to be 0;
      if(lenCheck < 0) return false;//return false if it is.
      int ENPlace = 0;//keeps track of the EN place.
      for(int i = lenCheck; i < oStringBytes.length;i++){//loops through and check the EN place.
        if(oStringBytes[i] != EN[ENPlace]){//checks the two bytes match
          return false;//return false if the bytes dont match.
        }
        ENPlace++;//adds one to the EN place.
      }
      return true;//return true if there are no errors.
    }
    catch(Exception e){return false;}
  }

  public String Encrypt(String oName)
  throws
  NoSuchPaddingException,
  NoSuchAlgorithmException,
  InvalidKeyException,
  BadPaddingException,
  IOException,
  IllegalBlockSizeException,
  InvalidAlgorithmParameterException,
  InvalidKeySpecException,
  Exception{
    Key secretKey = CodeInstance.getPassword();
    Cipher cipher = Cipher.getInstance(TRANSFORM);//gets the cypher and the transform being used.
    byte[] IV = new byte[IVSIZE];//creates a new IV byte array.
    SecureRandom secureRandom = new SecureRandom();//generates a new random IV to be used.
    secureRandom.nextBytes(IV);//gets the random bytes for the IV.
    IvParameterSpec ivspec = new IvParameterSpec(IV);//gets the IV parameter.
    cipher.init(Cipher.ENCRYPT_MODE,secretKey,ivspec);//loads up the cipher with the mode key and iv.
    byte[] aName = cipher.doFinal(oName.getBytes());//encrypts the string.
    aName = addTail(aName, IV);
    String encodedaName = Base64.getEncoder().encodeToString(aName);//encodes the string to base64.
    return encodedaName;//returns the new encrypted encode string.
  }

  public String Decrypt(String oName)
  throws
  NoSuchPaddingException,
  NoSuchAlgorithmException,
  InvalidKeyException,
  BadPaddingException,
  IOException,
  IllegalBlockSizeException,
  InvalidAlgorithmParameterException,
  InvalidKeySpecException,
  Exception{
    Key secretKey = CodeInstance.getPassword();
    Cipher cipher = Cipher.getInstance(TRANSFORM);//gets the cipher with the correct transform.
    byte[] decodedoName = Base64.getDecoder().decode(oName);//decodes the string into bytes from base64.
    byte[] IV = getIV(decodedoName);
    IvParameterSpec ivspec = new IvParameterSpec(IV);//get the IV parameter.
    cipher.init(Cipher.DECRYPT_MODE,secretKey,ivspec);//loads the cipher with the mode key and iv.
    decodedoName = removeTail(decodedoName);
    byte[] aName = cipher.doFinal(decodedoName);//decrypts the data.
    return new String(aName);//returns the new unencrypted string.
  }

  public String Decrypt(String oName, boolean ignoreSigniture)
  throws
  NoSuchPaddingException,
  NoSuchAlgorithmException,
  InvalidKeyException,
  BadPaddingException,
  IOException,
  IllegalBlockSizeException,
  InvalidAlgorithmParameterException,
  InvalidKeySpecException,
  Exception{
    checkSigniture = ignoreSigniture;
    String returnData = Decrypt(oName);
    checkSigniture = true;
    return returnData;
  }

}
