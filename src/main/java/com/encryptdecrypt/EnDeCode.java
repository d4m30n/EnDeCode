package com.encryptdecrypt;

import com.encryptdecrypt.*;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java .security.SecureRandom;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.Key;
import org.apache.commons.io.IOUtils;

public class EnDeCode{
  private static final String ALGORITHAM = "RSA";
  private static final java.io.File DATA_STORE_DIR = new java.io.File(System.getProperty("user.home"), ".credentials/driveEncrypt");
  private static final String PUBLICKEYNAME = "PublicKey";//the name of the Public key.
  private static final String PRIVATEKEYNAME = "PrivateKey";//the name of the private key.
  protected static final int KEYSIZE = 128;
  private static EnDeCode instance = null;//holds the instance for this.
  private Key password; //holds the password being used for encryption
  private PrivateKey privateKey;//holds the private key for signing.
  private PublicKey publicKey;//holds the public key for others to check signiture.

  protected static EnDeCode getInstance(String key) throws Exception{
    if(instance == null){//gets a new instance of the class if null.
      instance = new EnDeCode(key);//gets a new instance setting the key to be used.
    }
    return instance;//returns the new instance.
  }

  protected Key getPassword(){
    if(password == null){
      System.out.println("Password is null");
    }
    return password;//returns the password used for encryption.
  }
  protected void setPassword(String key) throws Exception{
    password = EncryptDecrypt.getKey(key);//sets the new password the generated key.
  }

  private EnDeCode(String key) throws Exception{
    setPassword(key);
  }

  protected void loadKeys(String key) throws Exception{
    try{
      FileInputStream fios = new FileInputStream(DATA_STORE_DIR.getAbsolutePath()+"/"+PRIVATEKEYNAME);//trys to load in the private key from file.
      byte[] privatek = IOUtils.toByteArray(fios);//gets the private key as a byte array.
      FileEncryptDecrypt decrypt = FileEncryptDecrypt.getInstance(key);//gets a new instance to decrypt the private key.
      EncryptDecrypt.checkSigniture = false;
      privatek = decrypt.Decrypt(privatek);//decrypts the private key.
      EncryptDecrypt.checkSigniture = true;
      fios.close();//closes the file stream.
      fios = new FileInputStream(DATA_STORE_DIR.getAbsolutePath()+"/"+PUBLICKEYNAME);//gets the public key.
      byte[] publick = IOUtils.toByteArray(fios);//loads the public key into the byte array.
      KeyFactory kf = KeyFactory.getInstance("RSA"); //gets the keyfactory instance to load public and private key.
      privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privatek));//sets the private key.
      publicKey = kf.generatePublic(new X509EncodedKeySpec(publick));//sets the public key.
    }
    catch(Exception e){
      e.printStackTrace();
      generateKey(key);//generates a new public and private key.
    }
  }


  protected byte[] genSigniture(byte[] data) throws Exception{
    Signature rsa = Signature.getInstance("SHA256withRSA");//sets the sigiture instance to be used.
    rsa.initSign(privateKey);//sets the key to be used for the signiture.
    rsa.update(data);//loads in the file to generate the signiture.
    byte[] sig = rsa.sign();//gets the byte array for the signiture.
    return sig;//returns the new signiture.
  }


  private void generateKey(String key) throws Exception{
    KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHAM);//set the algoritan to use for the key pair.
    SecureRandom rand = new SecureRandom();//gets a new secure random instance.
    kpg.initialize(1024,rand);//sets the key size.
    KeyPair keyPair = kpg.generateKeyPair();//generates a new key pair.
    privateKey = keyPair.getPrivate();//saves the privae key.
    publicKey = keyPair.getPublic();//saves the public key.
    byte[] privatek = privateKey.getEncoded();//gets the private key as a byte array.
    FileEncryptDecrypt encrypt = FileEncryptDecrypt.getInstance(key);//gets a new instance of the file encrypt.
    privatek = encrypt.Encrypt(privatek);//encrypts the private key.
    byte[] publick = publicKey.getEncoded();//gets the public key as a byte array.
    FileOutputStream fios = new FileOutputStream(DATA_STORE_DIR.getAbsolutePath()+"/"+PRIVATEKEYNAME);//file stream to write out the pirvate key.
    fios.write(privatek);//writes out the private key.
    fios.close();//closes the file stream.
    fios = new FileOutputStream(DATA_STORE_DIR.getAbsolutePath()+"/"+PUBLICKEYNAME);//file stream to wirte out the public key.
    fios.write(publick);//writes out the public key.
    fios.close();//closes the file stream.
  }
}
