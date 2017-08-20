package EncryptDecrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;

public class EncryptDecrypt{
  private static final String ALGORITHM = "AES";
  private static final String TRANSFORM = "AES/CBC/PKCS5Padding";
  private static final byte[] IV = new byte[16];
  private static final byte[] EN = "e".getBytes();

  public static boolean isEncrypted(String oString){
    try{
      byte[] oStringBytes = Base64.getDecoder().decode(oString);
      int lenCheck = oStringBytes.length-EN.length+1;
      if(lenCheck < 0) return false;
      int ENPlace = 0;
      for(int i = lenCheck; i < oStringBytes.length;i++){
        System.out.println("SBYTE: "+oStringBytes[i]+"\nEBYTE: "+EN[ENPlace]);
        if(oStringBytes[i] != EN[ENPlace]){
          return false;
        }
        ENPlace++;
      }
      return true;
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
  InvalidAlgorithmParameterException{
    Key secretKey = new SecretKeySpec(key.getBytes(),ALGORITHM);
    Cipher cipher = Cipher.getInstance(TRANSFORM);
    IvParameterSpec ivspec = new IvParameterSpec(IV);
    cipher.init(cipherMode, secretKey, ivspec);
    byte[] outputBytes = cipher.doFinal(original);
    return outputBytes;
  }

  private static String ApplyEncryptionString(String oName, String key)
  throws
  NoSuchPaddingException,
  NoSuchAlgorithmException,
  InvalidKeyException,
  BadPaddingException,
  IOException,
  IllegalBlockSizeException,
  InvalidAlgorithmParameterException{
    Key secretKey = new SecretKeySpec(key.getBytes(),ALGORITHM);
    Cipher cipher = Cipher.getInstance(TRANSFORM);
    IvParameterSpec ivspec = new IvParameterSpec(IV);
    cipher.init(Cipher.ENCRYPT_MODE,secretKey,ivspec);
    byte[] aName = cipher.doFinal(oName.getBytes());
    byte[] returnName = new byte[aName.length+EN.length];
    for(int i = 0; i < aName.length;i++){
      returnName[i] = aName[i];
    }
    for(int i = aName.length; i < EN.length;i++){
      returnName[i] = EN[i];
    }
    String encodedaName = Base64.getEncoder().encodeToString(returnName);
    return encodedaName;
  }

  private static String ApplyDecryptionString(String oName, String key)
  throws
  NoSuchPaddingException,
  NoSuchAlgorithmException,
  InvalidKeyException,
  BadPaddingException,
  IOException,
  IllegalBlockSizeException,
  InvalidAlgorithmParameterException{
    Key secretKey = new SecretKeySpec(key.getBytes(),ALGORITHM);
    Cipher cipher = Cipher.getInstance(TRANSFORM);
    IvParameterSpec ivspec = new IvParameterSpec(IV);
    cipher.init(Cipher.DECRYPT_MODE,secretKey,ivspec);
    byte[] decodedoName = Base64.getDecoder().decode(oName);
    byte[] removedtail = new byte[decodedoName.length-EN.length];
    for(int i = 0; i < decodedoName.length-EN.length;i++){
      removedtail[i] = decodedoName[i];
    }
    byte[] aName = cipher.doFinal(removedtail);
    return new String(aName);
  }

  public static String EncryptString(String name, String key)
  throws
  NoSuchPaddingException,
  NoSuchAlgorithmException,
  InvalidKeyException,
  BadPaddingException,
  IOException,
  IllegalBlockSizeException,
  InvalidAlgorithmParameterException{
    return ApplyEncryptionString(name,key);
  }
  public static String DecryptString(String name, String key)
  throws
  NoSuchPaddingException,
  NoSuchAlgorithmException,
  InvalidKeyException,
  BadPaddingException,
  IOException,
  IllegalBlockSizeException,
  InvalidAlgorithmParameterException{
    return ApplyDecryptionString(name,key);
  }
}
