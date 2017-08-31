package com.endecode;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import org.apache.commons.io.IOUtils;

public class RSAS extends AES{

  //Static Final Veriables
  protected static final int SIGSIZE = 128;
  private static final String SIGSTRING = "SHA256withRSA";
  private static final String DEFAULTSAVE = ".credentials";
  private static final String PRIVATENAME = "privateKey";
  private static final String PUBLICNAME = "publicKey";
  protected static final String ALGORITHAM = "RSA";

protected PrivateKey privateKey;
protected ArrayList<PublicKey> publicKeys;

  public RSAS(String password) throws Exception{
    this(password,DEFAULTSAVE,false);
  }

  public RSAS(String password,String saveLocation) throws Exception{
    this(password,saveLocation,false);
  }

  public RSAS(String password,String saveLocation, boolean genNewKeys) throws Exception{
    super(password);
    if(saveLocation == null) saveLocation = DEFAULTSAVE;
    if(genNewKeys){
      if(!genKeys(saveLocation)) throw new Exception("Could Not Generate New Keys");
    }
    else{
      loadKeys(saveLocation);
    }
  }

  private boolean loadKeys(String saveLocation) throws Exception{
    try{
      FileInputStream fios = new FileInputStream(saveLocation+"/"+PRIVATENAME);//trys to load in the private key from file.
      byte[] privatek = IOUtils.toByteArray(fios);//gets the private key as a byte array.
      privatek = super.decrypt(privatek);//decrypt the private key.
      fios.close();//closes the file stream.
      fios = new FileInputStream(saveLocation+"/"+PUBLICNAME);//gets the public key.
      byte[] publick = IOUtils.toByteArray(fios);//loads the public key into the byte array.
      KeyFactory kf = KeyFactory.getInstance("RSA"); //gets the keyfactory instance to load public and private key.
      privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privatek));//sets the private key.
      publicKeys.add(kf.generatePublic(new X509EncodedKeySpec(publick)));//sets the public key.
    }
    catch(FileNotFoundException e){
      return genKeys(saveLocation);
    }
    return true;
  }

  private boolean genKeys(String saveLocation){
    try{
      KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHAM);//set the algoritan to use for the key pair.
      SecureRandom rand = new SecureRandom();//gets a new secure random instance.
      kpg.initialize(1024,rand);//sets the key size.
      KeyPair keyPair = kpg.generateKeyPair();//generates a new key pair.
      privateKey = keyPair.getPrivate();//saves the privae key.
      publicKeys.add(keyPair.getPublic());
      byte[] privatek = super.encrypt(privateKey.getEncoded());
      FileOutputStream fios = new FileOutputStream(saveLocation+"/"+PRIVATENAME);//file stream to write out the pirvate key.
      fios.write(privatek);//writes out the private key.
      fios.close();//closes the file stream.
      fios = new FileOutputStream(saveLocation+"/"+PUBLICNAME);//file stream to wirte out the public key.
      fios.write(keyPair.getPublic().getEncoded());//writes out the public key.
      fios.close();//closes the file stream.
    }
    catch(Exception e){
      return false;
    }
    return true;
  }

  @Override
  public byte[] encrypt(byte[] data) throws Exception{
    data = super.encrypt(data);//encrypts the incoming data adding AES tails.
    data = addSignature(data);//generates a signiture for the encrypted data.
    return data;//returns the encrypted data with the tail.
  }

  @Override
  public byte[] decrypt(byte[] data) throws Exception{
    data = removeSigniture(data);
    data = super.decrypt(data);//decrypts the data with signiture removed.
    return data;//returns the decrypted data.
  }

  private boolean valSigniture(byte[] data, byte[] signature) throws Exception{
    Signature sig = Signature.getInstance(SIGSTRING);//loads in the signature
    for(PublicKey p : publicKeys){//checks all the public keys avalable.
      sig.initVerify(p);//load in the public key.
      sig.update(data);//load in the data.
      boolean result = sig.verify(signature);//check the signiture agains the current one.
      if(result)//check if the result is true.
        return true;//return true if a public key match is found.
    }
    return false;//return false after checking all keys and none found.
  }

  /**
   * generate a sinature based on the data given
   * @param data the data to generate a signature
   * @return the signature that has been generated.
   */
  private byte[] genSigniture(byte[] data) throws Exception{
    Signature sig = Signature.getInstance(SIGSTRING);//gets the signiture instance.
    sig.initSign(privateKey);//loads in the key that will be used.
    sig.update(data);//loads in the data to sign
    return sig.sign();//returns the byte[] signiture.
  }

  /**
   * Removes the signature for the byte[] to get just the data.
   * @param data the data with the signature on the end.
   * @return the data without the signature on the end.
   */
  protected byte[] removeSigniture(byte[] data) throws Exception{
    byte[] tmp = data;//holds the data with the signiture.
    byte[] sig = new byte[SIGSIZE];//holds just the signiture.
    data = new byte[tmp.length-SIGSIZE];//holds just the data.
    for(int i = 0; i < tmp.length; i++){
      if(i == tmp.length-SIGSIZE){//checks what part of the array i is at.
        sig[(i + SIGSIZE) - tmp.length] = tmp[i];//adds the signiture to the byte[]
      }
      else{
        data[i] = tmp[i];//removes the signiture from the data.
      }
    }
    //remove the signituer from the data
    if(!valSigniture(data,sig))//checks if the signiture is valid.
      throw new Exception("Signitures Do Not Match");
    return data;//returns just the data.
  }

  /**
   * Adds the signature to the end of the data array.
   * @param data the data[] to sign and add the signature to the end of.
   * @return the data with the signature on the end.
   */
  protected byte[] addSignature(byte[] data) throws Exception{
    byte[] tmp = data;
    byte[] sig = genSigniture(tmp);
    data = new byte[tmp.length+SIGSIZE];
    for(int i = 0; i < data.length; i++){
      if(i == data.length-SIGSIZE){
        data[i] = sig[(i+SIGSIZE)-data.length];
      }
      else{
        data[i] = tmp[i];
      }
    }
    return data;
  }
}