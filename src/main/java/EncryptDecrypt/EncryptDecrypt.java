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
    String encodedaName = Base64.getEncoder().encodeToString(aName);
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
    byte[] aName = cipher.doFinal(decodedoName);
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
