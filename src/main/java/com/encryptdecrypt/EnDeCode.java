package com.endecode;

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
import org.apache.commons.io.IOUtils;

public class EnDeCode{
  private static final String ALGORITHAM = "RSA";
  private static final java.io.File DATA_STORE_DIR = new java.io.File(System.getProperty("user.home"), ".credentials/driveEncrypt");
  private static final String PUBLICKEYNAME = "PublicKey";
  private static final String PRIVATEKEYNAME = "PrivateKey";
  private PrivateKey privateKey;
  private PublicKey publicKey;

  public EnDeCode(String password, boolean genNew) throws Exception{
    if(genNew){
      generateKey(password);
    }
    else{
      FileInputStream fios = new FileInputStream(DATA_STORE_DIR.getAbsolutePath()+"/"+PRIVATEKEYNAME);
      byte[] privatek = IOUtils.toByteArray(fios);
      privatek = FileEncryptDecrypt.Decrypt(privatek, password);
      fios.close();
      fios = new FileInputStream(DATA_STORE_DIR.getAbsolutePath()+"/"+PUBLICKEYNAME);
      byte[] publick = IOUtils.toByteArray(fios);
      KeyFactory kf = KeyFactory.getInstance("RSA"); // or "EC" or whatever
      privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privatek));
      publicKey = kf.generatePublic(new X509EncodedKeySpec(publick));
    }
  }


  private byte[] genSigniture(byte[] data){
    Signature rsa = Signature.getInstance("SHA256withRSA");
    rsa.initSign(privateKey);
    rsa.update(data);
    byte[] sig = rsa.sign();
  }


  private void generateKey(String password) throws Exception{
    KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHAM);
    SecureRandom rand = new SecureRandom();
    kpg.initialize(1024,rand);
    KeyPair keyPair = kpg.generateKeyPair();
    privateKey = keyPair.getPrivate();
    publicKey = keyPair.getPublic();
    byte[] privatek = privateKey.getEncoded();
    privatek = FileEncryptDecrypt.Encrypt(privatek,password);
    byte[] publick = publicKey.getEncoded();
    FileOutputStream fios = new FileOutputStream(DATA_STORE_DIR.getAbsolutePath()+"/"+PRIVATEKEYNAME);
    fios.write(privatek);
    fios.close();
    fios = new FileOutputStream(DATA_STORE_DIR.getAbsolutePath()+"/"+PUBLICKEYNAME);
    fios.write(publick);
    fios.close();
  }
}
