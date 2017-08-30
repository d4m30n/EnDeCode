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
  protected static EnDeCode CodeInstance = null;//holds the instance for the public and private keys.
  protected static byte[] currentSigniture = null;//just holds the current generated Signiture.
  protected static boolean checkSigniture = true;//indecates weather the signiture should be checked.

  /**
    * generates the key that will be used to encrypt the data.
    * @param password the password that the user knows used to generate the key.
    * @return returns the secretKey that is used to encrypt the data.
    **/
  protected static SecretKey getKey(String password)
  throws
  InvalidKeySpecException,
  NoSuchAlgorithmException{
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");//sets the deviation function to be used.
    PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), SALT ,65536, 128);//gets the new 128 key to be used.
    SecretKey tmp = factory.generateSecret(spec);//getst the secretKey from the PBEKeySpec.
    return new SecretKeySpec(tmp.getEncoded(), ALGORITHM);//returns the new key with the algoritham being used.
  }

  /**
    * Given a byte array the iv will then be added to the point given.
    * @param data the byte array the the IV should be added to.
    * @param IV the byte array holding the IV used in encryption.
    * @param place the start place in the array the IV should be added to.
    * @return the end place the IV was added to.
    **/
  private static int addIV(byte[] data, byte[] IV, int place){
    for(byte a : IV){//loops through the whole iv.
      data[place] = a;//add the iv to the plave in the data.
      place++;//increace the place in the data.
    }
    return place;//returns the end place used.
  }

  /**
    * adds the signiture to the data using the place given to the methord.
    * @param data holds the byte array to add the data to
    * @param input the byte array that the signiture will be generated for.
    * @param place holds the start place the signiture will be writen to.
    * @return the end place where the signiture is finished added to.
    **/
  private static int addSignniture(byte[] data,byte[] input,int place) throws Exception{
    byte[] sig = CodeInstance.genSigniture(input);//gets the signiture byte array.
    for(byte a : sig){//loops through the signiture.
      data[place] = a;//adds the signiture to the place in the data.
      place++;//adds one to the place.
    }
    return place;//returns the place where the signiuter ends.
  }

  /**
    * adds the encryption check byte array the the end of the data.
    * @param data the byte array the EN byte array is added to.
    * @param place the start place in the array for the data.
    * @return the end place that the EN stoped not this should be equal to the lenght of the whole array.
    **/
  private static int addEN(byte[] data, int place){
    for(byte a : EN){//loops through the EN byte array.
      data[place] = a;//adds the EN byte to the data.
      place++;//increaces the place by one.
    }
    return place;//return the end place for the data.
  }

  /**
    * adds the tail data to the end of the encrypted data.
    * @param data holds the original encrypted data.
    * @param IV holds the IV that was used to encrypt the data.
    * @return the byte array holding the tail added to the end.
    **/
  protected static byte[] addTail(byte[] data, byte[] IV) throws Exception{
    byte[] tmp = data;//holds the old data tmpareroly.
    data = new byte[tmp.length+tailSize];//creates a new data array with the tail size.
    int place = 0;//gives the starting place in the array.
    for(byte a : tmp){//loops through the original data and adds it to the end of the new data array.
      data[place] = a;//adds the data from tmp to data[]
      place++;//increaces the place by one.
    }
    place = addIV(data,IV,place);//adds the iv to the data from the place
    place = addSignniture(data,tmp,place);//adds the signiture to the data from the place.
    place = addEN(data, place);//adds the encryption byte[] onto the data.
    return data;//returns the data with the tail added to the end.
  }

  /**
    * This removes the tail that is on the end of the data.
    * @param data the byte array of the data with the tail on the end.
    * @return the byte[] containing just the data.
    **/
  protected static byte[] removeTail(byte[] data) throws Exception{
    if(checkSigniture){//checks to see if the signiture should be checked.
      getSigniture(data);//gets the signiture from the data.
    }
    byte[] tmp = data;//holds the data tmpareroly.
    data = new byte[tmp.length-tailSize];//new byte[] with the tail sized removed.
    for(int i = 0; i < data.length; i++){//loops all the data size and then adds it to the new array.
      data[i] = tmp[i];//adds the data in tmp to the new array.
    }
    if(checkSigniture){//checks to see if the signiture should be checked.
      byte[] sig = CodeInstance.genSigniture(data);//gets the signiture form the data.
      for(int i = 0; i < sig.length; i++){//loops through the size of the signiture.
        if(currentSigniture[i] != sig[i]){//checks if the two places in the array are the same.
          throw new Exception("INVALID SIGNITURE");//throws an exception if the signitures do not match.
        }
      }
    }
    return data;//returns the data without the tail on the end.
  }

  /**
    * This gets the signiture from the tail end of the data.
    * @param data the data containing the tail.
    **/
  protected static void getSigniture(byte[] data){
    byte[] sig = new byte[EnDeCode.KEYSIZE];//creates an array large enough to hold the signiture.
    int place = data.length-tailSize+IVSIZE;//gets the starting place for the signiture.
    int SIGPlace = 0;//gets the place for the array at the start.
    for(int i = data.length-tailSize+IVSIZE; i < data.length-EN.length; i++){//loops through the signityre till at the end.
      sig[SIGPlace] = data[i];//gets the signituer from the data and adds it to the sig array.
      SIGPlace++;//increaces the signiture place by one.
    }
    currentSigniture = sig;//sets the static array above with the new signiture.
  }

  /**
    * This gets the IV from the data with a tail.
    * @param data the byte[] with the data and the tail
    * @return a byte[] that holds the IV used.
    **/
  protected static byte[] getIV(byte[] data){
    byte[] IV = new byte[IVSIZE];//creates a new array to hold the IV.
    int DPlace = data.length-tailSize;//gets the place for the IV at the start of the tail.
    for(int i = 0; i < IV.length; i++){//loops through the size of the new array.
      IV[i] = data[DPlace];//adds the byte to the new IV array.
      DPlace++;//increaces the place for the data by one.
    }
    return IV;//returns the IV from the tail.
  }

}
