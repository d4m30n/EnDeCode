package EncryptDecrypt;

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
  private static final String ALGORITHM = "AES";//holds the algorithan that is being used.
  private static final String TRANSFORM = "AES/CBC/PKCS5Padding";//holds the algoritham transform used.
  private static final int IVSIZE = 16;//holds the size that iv is going to be.
  private static final byte[] EN = "e".getBytes();//holds the byte that signals encryption.
  private static final byte[] SALT = "dd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315d".getBytes();

  private static SecretKey getKey(String password,String salt)
  throws
  InvalidKeySpecException,
  NoSuchAlgorithmException{
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");//sets the deviation function to be used.
    PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), SALT ,65536, 128);//gets the new 128 key to be used.
    SecretKey tmp = factory.generateSecret(spec);//getst the secretKey from the PBEKeySpec.
    return new SecretKeySpec(tmp.getEncoded(), ALGORITHM);//returns the new key with the algoritham being used.
  }

  public static boolean isEncrypted(String oString){
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

  public static boolean isEncrypted(byte[] oData){
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

  protected static byte[] Apply(int cipherMode, byte[] original, String key)
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

  private static String ApplyEncryptionString(String oName, String key)
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
    Cipher cipher = Cipher.getInstance(TRANSFORM);//gets the cypher and the transform being used.
    byte[] IV = new byte[IVSIZE];//creates a new IV byte array.
    SecureRandom secureRandom = new SecureRandom();//generates a new random IV to be used.
    secureRandom.nextBytes(IV);//gets the random bytes for the IV.
    IvParameterSpec ivspec = new IvParameterSpec(IV);//gets the IV parameter.
    cipher.init(Cipher.ENCRYPT_MODE,secretKey,ivspec);//loads up the cipher with the mode key and iv.
    byte[] aName = cipher.doFinal(oName.getBytes());//encrypts the string.
    byte[] returnName = new byte[aName.length+EN.length+IVSIZE];//creates a new array that adds room for the tail on the end.
    int bytesDone = 0;//keeps track of the bytes that have been done.
    for(int i = bytesDone; i < aName.length;i++){//loops through the encrypted data and adds to the new array.
      returnName[i] = aName[i];bytesDone++;//adds the data to array and adds one to the bytes done.
    }
    int IVPlace = 0;//keeps track of the IV place.
    for(int i = bytesDone; i < returnName.length-EN.length; i++){//loops through and adds the IV to the end of the data.
      returnName[i] = IV[IVPlace];IVPlace++;bytesDone++;//adds the iv to the end of the data and adds one to the bytes done.
    }
    int ENPlace = 0;//keeps track of the EN place.
    for(int i = bytesDone; i <returnName.length;i++){//loops through and adds the ecrypted byte to the end.
      returnName[i] = EN[ENPlace];ENPlace++;bytesDone++;//adds the EN byte and adds one to the bytes done.
    }
    String encodedaName = Base64.getEncoder().encodeToString(returnName);//encodes the string to base64.
    return encodedaName;//returns the new encrypted encode string.
  }

  private static String ApplyDecryptionString(String oName, String key)
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
    Cipher cipher = Cipher.getInstance(TRANSFORM);//gets the cipher with the correct transform.
    byte[] decodedoName = Base64.getDecoder().decode(oName);//decodes the string into bytes from base64.
    byte[] IV = new byte[IVSIZE];//gets the new IV array.
    int IVPlace = 0;//keeps track of the IV place.
    for(int i = decodedoName.length-EN.length-IVSIZE; i < decodedoName.length-EN.length; i++){//loops through and gets the IV array.
      IV[IVPlace] = decodedoName[i];IVPlace++;//adds the IV array to be used.
    }
    IvParameterSpec ivspec = new IvParameterSpec(IV);//get the IV parameter.
    cipher.init(Cipher.DECRYPT_MODE,secretKey,ivspec);//loads the cipher with the mode key and iv.
    byte[] removedtail = new byte[decodedoName.length-EN.length-IVSIZE];//create a smaler array to hold just the data.
    for(int i = 0; i < decodedoName.length-EN.length-IVSIZE;i++){//loops through the array removing the tail end.
      removedtail[i] = decodedoName[i];//puts the data in the new array.
    }
    byte[] aName = cipher.doFinal(removedtail);//decrypts the data.
    return new String(aName);//returns the new unencrypted string.
  }

  public static String EncryptString(String name, String key)
  throws
  NoSuchPaddingException,
  NoSuchAlgorithmException,
  InvalidKeyException,
  BadPaddingException,
  IOException,
  IllegalBlockSizeException,
  InvalidAlgorithmParameterException,
  InvalidKeySpecException{
    return ApplyEncryptionString(name,key);//encrypt the given string.
  }
  public static String DecryptString(String name, String key)
  throws
  NoSuchPaddingException,
  NoSuchAlgorithmException,
  InvalidKeyException,
  BadPaddingException,
  IOException,
  IllegalBlockSizeException,
  InvalidAlgorithmParameterException,
  InvalidKeySpecException{
    return ApplyDecryptionString(name,key);//decrypt the given string.
  }
}
