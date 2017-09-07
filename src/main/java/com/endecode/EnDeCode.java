package com.endecode;

import java.security.Key;

import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

class EnDeCode{

  private Key password;

  protected static final String DNE = "This data is not encrypted.";//error to return if the data is not encrypted
  protected static final String ALGORITHM = "AES";//holds the algorithan that is being used.
  protected static final String TRANSFORM = "AES/CBC/PKCS5Padding";//holds the algoritham transform used.
  private static final byte[] SALT = "dd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315ddd54f6g7rv2315d".getBytes();//the salt being used for the password
  private static final byte[] EN = "e".getBytes();

  protected EnDeCode(String password) throws Exception{
    this.password = getKey(password);
  }

  /**
   * This loads in and generates the key that will be used for encryption and decryption
   * @param password the password the user is using.
   * @return the secrate key that was generated
   */
  private static SecretKey getKey(String password) throws Exception{
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");//sets the deviation function to be used.
    PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), SALT ,65536, 128);//gets the new 128 key to be used.
    SecretKey tmp = factory.generateSecret(spec);//getst the secretKey from the PBEKeySpec.
    return new SecretKeySpec(tmp.getEncoded(), ALGORITHM);//returns the new key with the algoritham being used.
  }
  protected Key getPassword(){
    return password;
  }

  /**
   * checks to see if the byte[] being given is encrypted or not
   * @param data the data that needs to be checked.
   * @return true if the encryption is valid false if not.
   */
  public boolean isEncrypted(byte[] data){
    int sPlace = data.length - EN.length;
    for(byte en : EN){
      if(data[sPlace] != en) return false;
      sPlace++;
    }
    return true;
  }

  public boolean isEncrypted(String data){
    return isEncrypted(Base64.getDecoder().decode(data));
  }

  protected byte[] removeEN(byte[] data) throws Exception{
    if(!isEncrypted(data)) throw new Exception(DNE);//checks if the data has the EN byte[]
    byte[] tmp = data;//holds the old data with the EN byte[]
    data = new byte[data.length - EN.length];//creates a new byte[] for the datai.
    System.arraycopy(tmp,0,data,0,data.length);//copy all the data back from tmp
    return data;//return the new data[].
  }

  protected byte[] addEN(byte[] data){
    byte[] tmp = data;
    data = new byte[tmp.length+EN.length];
    System.arraycopy(tmp,0,data,0,tmp.length);
    System.arraycopy(EN,0,data,tmp.length,EN.length);
    return data;
  }
}