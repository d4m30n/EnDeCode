package com.endecode;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.nio.file.Files;
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
import java.util.Base64;

public class RSAS extends AES{

  //Static Final Veriables
  protected static final int SIGSIZE = 128;//this is the size of a signature based off of a key size of 1024.
  private static final String SIGSTRING = "SHA256withRSA";//the signature to use when generating sinatures for the data.
  private static final String DEFAULTSAVE = ".credentials";//The default place to store the keys.
  private static final String PRIVATENAME = "privateKey";//The name for the private key.
  private static final String PUBLICNAME = "publicKey";//The name for the public keys.
  protected static final String ALGORITHAM = "RSA";//The algoritham to use.

  protected PrivateKey privateKey;//The veriable to hold the private key.
  protected ArrayList<PublicKey> publicKeys;//the veriable to hold the public key.

  /**
   * This is the basic constructor that just takes a password to use.
   * @param password this is the password being used for encryption
   */
  public RSAS(String password) throws Exception{
    this(password,DEFAULTSAVE,false);//calls the default constructor.
  }

  /**
   * This is the second constructor that allows the user to set a save location for where to load the keys.
   * @param password the password to use for encryption and decryption.
   * @param saveLocation the location of the keys if on other than the default is used.
   */
  public RSAS(String password,String saveLocation) throws Exception{
    //remove the / if it is on the end of the saveLocation.
    this(password,saveLocation,false);//calls the default constructor
  }

  /**
   * This is another constructor allowing the user to set the password and generate new keys.
   * @param password the password to use for encryption and decryption
   * @param genNewKeys a boolean indecating weather or not to generate new keys.
   */
  public RSAS(String password,boolean genNewKeys) throws Exception{
    this(password,DEFAULTSAVE,genNewKeys);
  }

  /**
   * This is the main consturctor that allows the user to set all the paramaters avalable.
   * @param password the password used for encryption and decryption
   * @param saveLocation the location to save or find the keys.
   * @param genNewKeys boolean indecating weather or not to generate new keys to use.
   */
  public RSAS(String password,String saveLocation, boolean genNewKeys) throws Exception{
    super(password);//call the super constructor with the password being used.
    if(saveLocation == null) saveLocation = DEFAULTSAVE;//if the save location is null pass in the default.
    if(password == null) throw new Exception("Password Cant be null");//checks to see if the password is null.
    if(genNewKeys){//check if the user wants new keys generated.
      if(!genKeys(saveLocation)) throw new Exception("Could Not Generate New Keys");//throw new exception in the keys could not be generated.
    }
    else{
      loadKeys(saveLocation);//attempt to load in the keys from file.
    }
  }



  /**
   * Loads in the keys that are being used from the save location.
   * @param saveLocation the location of where the keys can be found.
   * @return weather the keys were loaded or not.
   */
  private boolean loadKeys(String saveLocation) throws Exception{
    try{
      File file = new File(saveLocation+"/"+PRIVATENAME);//trys to load in the private key from file.
      byte[] privatek = Files.readAllBytes(file.toPath());
      privatek = super.decrypt(privatek);//decrypt the private key.
      file = new File(saveLocation+"/"+PUBLICNAME);//gets the public key.
      byte[] publick = Files.readAllBytes(file.toPath());
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
  public String encrypt(String data) throws Exception{
    byte[] byteData = data.getBytes();
    byteData = encrypt(byteData);
    data = Base64.getEncoder().encodeToString(byteData);
    return data;
  }

  @Override
  public byte[] decrypt(byte[] data) throws Exception{
    data = removeSigniture(data);
    data = super.decrypt(data);//decrypts the data with signiture removed.
    return data;//returns the decrypted data.
  }
  public String decrypt(String data) throws Exception{
    byte[] byteData = Base64.getDecoder().decode(data);
    byteData = decrypt(byteData);
    data = new String(byteData);
    return data;
  }

  /**
   * Checks to see if the data given is encrypted or not.
   * NOTE: this will also validate the signature at the same time.
   * @param data the data that needs to be checked.
   * @return boolean indecating weather the data is encrypted or not.
   */
  public boolean isEncrypted(byte[] data){
    try{
      return super.isEncrypted(removeSigniture(data));//call the super class with the signature removed.
    }
    catch(Exception e){
      return false;//return false if the signatuer is not valid.
    }
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
    if(tmp.length-SIGSIZE <= 0) throw new Exception("The data is not valid");
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