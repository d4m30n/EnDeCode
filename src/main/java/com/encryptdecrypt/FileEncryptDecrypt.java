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

public class FileEncryptDecrypt extends StringEncryptDecrypt{

  public static boolean isEncrypted(byte[] oData){
    //test
    try{//catches an and all errors.
      int lenCheck = oData.length-EN.length;//checks to make sure the lenght is not less than 0;
      if(lenCheck < 0) return false;//return false if the lenght is less that 0.
      int ENPlace = 0;//keeps track of the EN place.
      for(int i = lenCheck; i < oData.length;i++){//loops through the en section and checks it matches.
        if(oData[i] != EN[ENPlace]){//check the end matches the one above.
          return false;//return false if they dont match.
        }
        ENPlace++;//adds one to the EN place.
      }
      return true;//return true if no errors.
    }
    catch(Exception e){return false;}
  }

  private static byte[] Apply(int cipherMode, byte[] original, String key)
  throws
  NoSuchPaddingException,
  NoSuchAlgorithmException,
  InvalidKeyException,
  BadPaddingException,
  IOException,
  IllegalBlockSizeException,
  InvalidAlgorithmParameterException,
  InvalidKeySpecException{
    Key secretKey = getKey(key,"");
    Cipher cipher = Cipher.getInstance(TRANSFORM);//loads in the cipher with the correct padding and aes format
    byte[] IV = new byte[IVSIZE];//creates a new IV byte array.
    if(cipherMode == Cipher.ENCRYPT_MODE){//checks to see if the file is being encrypted.
      SecureRandom secureRandom = new SecureRandom();//gets a new random number generator.
      secureRandom.nextBytes(IV);//generates a new random IV.
    }
    else{//if the file is being decrypted.
      int IVPlace = 0;//holds the palce in the IV array.
      for(int i = original.length-EN.length-IVSIZE; i < original.length-EN.length; i++){//loops through the IV bytes stored in the array.
        IV[IVPlace] = original[i];IVPlace++;//adds the IV to the IV array.
      }
    }
    IvParameterSpec ivspec = new IvParameterSpec(IV);//gets the IV paramater.
    cipher.init(cipherMode, secretKey, ivspec);//loads in the cipher with the mode key and iv.
    if(cipherMode == Cipher.DECRYPT_MODE){//if the cypher is decrypting remove the tail bytes on the end.
      byte[] tmp = original;//holds the original undecrypted array.
      original = new byte[original.length-EN.length-IVSIZE];//creates the new smaller array.
      for(int i = 0; i < original.length; i++){//loops through only adding the data to be decrypted.
        original[i] = tmp[i];//adds the data one byte at a time.
      }
    }
    byte[] outputBytes = cipher.doFinal(original);//encrypts the bytes or decrypts depending.
    if(cipherMode == Cipher.ENCRYPT_MODE){//if the file is being encrypted add the tail bytes.
      byte[] tmp = outputBytes;//holds the original encrypted bytes.
      int bytesDone = 0;//keeps track of the number of bytes that are done.
      outputBytes = new byte[outputBytes.length+EN.length+IVSIZE];//creates the new larger array to hold information.
      for(int i = bytesDone; i < tmp.length; i++){//adds the encrypted data to the new byte array.
        outputBytes[i] = tmp[i];bytesDone++;//adds the data and adds one to the bytes done.
      }
      int IVPlace = 0;//holds the iv place.
      for(int i = bytesDone; i < outputBytes.length-EN.length; i++){//loops through and adds the IV to the file.
        outputBytes[i] = IV[IVPlace];IVPlace++;bytesDone++;//adds the IV and add one to the bytes done.
      }
      int ENPlace = 0;//keeps track of the EN place.
      for(int i = bytesDone; i < outputBytes.length; i++){//loops through and adds the byte to say its encrypted.
        outputBytes[i] = EN[ENPlace];ENPlace++;bytesDone++;//adds the encryption byte and adds one to bytes done.
      }
    }
    return outputBytes;//reurns the final byte array.
  }

  public static byte[] Encrypt(byte[] original, String key)
  throws
  NoSuchPaddingException,
  NoSuchAlgorithmException,
  InvalidKeyException,
  BadPaddingException,
  IOException,
  IllegalBlockSizeException,
  InvalidAlgorithmParameterException,
  InvalidKeySpecException{
    return Apply(Cipher.ENCRYPT_MODE, original, key);
  }

  public static byte[] Decrypt(byte[] original, String key)
  throws
  NoSuchPaddingException,
  NoSuchAlgorithmException,
  InvalidKeyException,
  BadPaddingException,
  IOException,
  IllegalBlockSizeException,
  InvalidAlgorithmParameterException,
  InvalidKeySpecException{
    return Apply(Cipher.DECRYPT_MODE, original, key);
  }
}
