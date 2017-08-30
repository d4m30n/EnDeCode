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
  protected FileEncryptDecrypt(){}
  private static FileEncryptDecrypt instance = null;//holds the FileEncrypt Instance.

  public static FileEncryptDecrypt getInstance(String password) throws Exception{
    return getInstance(password,false);
  }

  /**
    * This gets the current instance for the FileEncryptDecrypt.
    * NOTE this algoritham will fail if the Private key is not used of the first go after that the password can be anything.
    * @param password The password that the user wants to use for the encryption
    * @return The instance for this class.
    **/
  public static FileEncryptDecrypt getInstance(String password, boolean genNewKeys) throws Exception{
    if(instance == null){//checks if the instance is null
      instance = new FileEncryptDecrypt();//gets new instance of the class.
    }
    if(CodeInstance == null || genNewKeys){//checks if the the code instance is null or the user wants new key.
      CodeInstance = EnDeCode.getInstance(password);//gets a new instance of EnDeCode with the password.
      CodeInstance.loadKeys(password, genNewKeys);//loads the keys from the file.
    }
    return (FileEncryptDecrypt) instance;//returns the new instance.
  }


  /**
    * This methord checks to see if the byte array it is given was encrypted by this class.
    * @param oData passes the data byte[] to be checked.
    * @return a boolean  true for if encrypted and false if not encrypted.
    **/
  public boolean isEncrypted(byte[] oData){
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

  /**
    * this applies the encryption to the data supplied in a byte[]
    * @param cipherMode sets weather this methord is encrypting or decrypting.
    * @param original the original data that is being passed into the methrod.\
    * @return returns the encrypted or decrypted data.
    **/
  private byte[] Apply(int cipherMode, byte[] original)
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
    Cipher cipher = Cipher.getInstance(TRANSFORM);//loads in the cipher with the correct padding and aes format
    byte[] IV = new byte[IVSIZE];//creates a new IV byte array.
    if(cipherMode == Cipher.ENCRYPT_MODE){//checks to see if the file is being encrypted.
      SecureRandom secureRandom = new SecureRandom();//gets a new random number generator.
      secureRandom.nextBytes(IV);//generates a new random IV.
    }
    else{//if the file is being decrypted.
      IV = getIV(original);
    }
    IvParameterSpec ivspec = new IvParameterSpec(IV);//gets the IV paramater.
    cipher.init(cipherMode, secretKey, ivspec);//loads in the cipher with the mode key and iv.
    if(cipherMode == Cipher.DECRYPT_MODE){//if the cypher is decrypting remove the tail bytes on the end.
      original = removeTail(original);
    }
    byte[] outputBytes = cipher.doFinal(original);//encrypts the bytes or decrypts depending.
    if(cipherMode == Cipher.ENCRYPT_MODE){//if the file is being encrypted add the tail bytes.
      outputBytes = addTail(outputBytes, IV);
    }
    return outputBytes;//reurns the final byte array.
  }

  /**
    * Used to encrypt the data sent to the methord.
    * @param original the originial data before encryption.
    * @return the data after encryption.
    **/
  public byte[] Encrypt(byte[] original)
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
    return Apply(Cipher.ENCRYPT_MODE, original);//returns the encrypted byte[]
  }

  /**
    * Used to decrypt the data given to the methord.
    * @param original the original encrypted data.
    * @return returns the decrypted byte array.
    **/
  public byte[] Decrypt(byte[] original)
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
    if(!(isEncrypted(original)))//checks to see if the data can be decrypted by this class.
      throw new IllegalBlockSizeException("invalid Encryption");
    return Apply(Cipher.DECRYPT_MODE, original);//returns the decrypted data.
  }

  /**
    * decrypts the data but ignores the signiture checking.
    * @param original the encrypted data.
    * @param ignoreSigniture boolean indecating weather or not to ignore the signiture on the byte[].
    * @return returns the decrypted data.
    **/
  public byte[] Decrypt(byte[] original, boolean ignoreSigniture)
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
    if(!(isEncrypted(original)))//check if the data can be decrypted.
      throw new IllegalBlockSizeException("invalid Encryption");
    checkSigniture = ignoreSigniture;//change the signiture check boolean to what the user wants.
    byte[] returnData = Apply(Cipher.DECRYPT_MODE, original);//returns the decrypted data.
    checkSigniture = true;//resets the signiture check to true for other calls.
    return returnData;//returns the decrypted data.
  }
}
