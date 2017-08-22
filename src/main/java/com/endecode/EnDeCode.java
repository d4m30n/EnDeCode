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
import org.apache.commons.io.IOUtils;

public class EnDeCode{
  private static final String ALGORITHAM = "RSA";
  private static final java.io.File DATA_STORE_DIR = new java.io.File(System.getProperty("user.home"), ".credentials/driveEncrypt");
  private PrivateKey privateKey;
  private PublicKey publicKey;

  public EnDeCode(String password, boolean genNew) throws Exception{
    if(genNew){
      generateKey(password);
    }
    else{
      FileInputStream fios = new FileInputStream(DATA_STORE_DIR.getAbsolutePath()+"/PrivateKey");
      byte[] privatek = IOUtils.toByteArray(fios);
      privatek = FileEncryptDecrypt.Decrypt(privatek, password);
      fios.close();
      fios = new FileInputStream(DATA_STORE_DIR.getAbsolutePath()+"/pubicKey");
      byte[] publick = IOUtils.toByteArray(fios);
      KeyFactory kf = KeyFactory.getInstance("RSA"); // or "EC" or whatever
      privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privatek));
      publicKey = kf.generatePublic(new X509EncodedKeySpec(publick));
    }
  }



  public void generateKey(String password) throws Exception{
    KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHAM);
    SecureRandom rand = new SecureRandom();
    kpg.initialize(1024,rand);
    KeyPair keyPair = kpg.generateKeyPair();
    privateKey = keyPair.getPrivate();
    publicKey = keyPair.getPublic();
    byte[] privatek = privateKey.getEncoded();
    privatek = FileEncryptDecrypt.Encrypt(privatek,password);
    byte[] publick = publicKey.getEncoded();
    FileOutputStream fios = new FileOutputStream(DATA_STORE_DIR.getAbsolutePath()+"/PrivateKey");
    fios.write(privatek);
    fios.close();
    fios = new FileOutputStream(DATA_STORE_DIR.getAbsolutePath()+"/PublicKey");
    fios.write(publick);
    fios.close();
  }
}
