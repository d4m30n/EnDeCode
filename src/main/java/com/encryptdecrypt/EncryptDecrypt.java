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

public class EncryptDecrypt{
  protected EncryptDecrypt(){}

  protected static final String ALGORITHM = "AES";//holds the algorithan that is being used.
  protected static final String TRANSFORM = "AES/CBC/PKCS5Padding";//holds the algoritham transform used.
  protected static final int IVSIZE = 16;//holds the size that iv is going to be.
  protected static final byte[] EN = "e".getBytes();//holds the byte that signals encryption.
  protected static final int tailSize = IVSIZE+EnDeCode.KEYSIZE+EN.length;//holds the number of bytes in the tail of the data
  private static final byte[] SALT = "dd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315d".getBytes();
  protected static EnDeCode CodeInstance = null;
  protected static byte[] currentSigniture = null;
  protected static boolean checkSigniture = true;

  protected static SecretKey getKey(String password)
  throws
  InvalidKeySpecException,
  NoSuchAlgorithmException{
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");//sets the deviation function to be used.
    PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), SALT ,65536, 128);//gets the new 128 key to be used.
    SecretKey tmp = factory.generateSecret(spec);//getst the secretKey from the PBEKeySpec.
    return new SecretKeySpec(tmp.getEncoded(), ALGORITHM);//returns the new key with the algoritham being used.
  }

  private static int addIV(byte[] data, byte[] IV, int place){
    for(byte a : IV){
      data[place] = a;
      place++;
    }
    return place;
  }
  private static int addSignniture(byte[] data,byte[] input,int place) throws Exception{
    byte[] sig = CodeInstance.genSigniture(input);
    for(byte a : sig){
      data[place] = a;
      place++;
    }
    return place;
  }
  private static int addEN(byte[] data, int place){
    for(byte a : EN){
      data[place] = a;
      place++;
    }
    return place;
  }

  protected static byte[] addTail(byte[] data, byte[] IV) throws Exception{
    byte[] tmp = data;
    data = new byte[tmp.length+tailSize];
    int place = 0;
    for(byte a : tmp){
      data[place] = a;
      place++;
    }
    place = addIV(data,IV,place);
    place = addSignniture(data,tmp,place);
    place = addEN(data, place);
    return data;
  }

  protected static byte[] removeTail(byte[] data) throws Exception{
    if(checkSigniture){
      getSigniture(data);
    }
    byte[] tmp = data;
    data = new byte[tmp.length-tailSize];
    for(int i = 0; i < data.length; i++){
      data[i] = tmp[i];
    }
    if(checkSigniture){
      byte[] sig = CodeInstance.genSigniture(data);
      for(int i = 0; i < sig.length; i++){
        if(currentSigniture[i] != sig[i]){
          throw new Exception("INVALID SIGNITURE");
        }
      }
    }
    return data;
  }

  protected static void getSigniture(byte[] data){
    byte[] sig = new byte[EnDeCode.KEYSIZE];
    int place = data.length-tailSize+IVSIZE;
    int SIGPlace = 0;
    for(int i = data.length-tailSize+IVSIZE; i < data.length-EN.length; i++){
      sig[SIGPlace] = data[i];
      SIGPlace++;
    }
    currentSigniture = sig;
  }

  protected static byte[] getIV(byte[] data){
    byte[] IV = new byte[IVSIZE];
    int DPlace = data.length-tailSize;
    for(int i = 0; i < IV.length; i++){
      IV[i] = data[DPlace];
      DPlace++;
    }
    return IV;
  }

}
