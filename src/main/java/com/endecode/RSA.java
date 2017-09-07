package com.endecode;

public class RSA extends RSAS{

  /**
   * takes a password and calls the super class
   * @param password the password to be used for encryption.
   */
  public RSA(String password) throws Exception{
    super(password);
  }

  /**
   * this encrypts data given using RSA encryption
   * @param data the data that will be encrypted.
   * @return a byte[] containting the encrypted data
   */
  public byte[] encrypt(byte[] data){
    return new byte[10];
  }

  /**
   * this takes data and decrypts it using RSA keys
   * @param data the data that will be decrypted
   * @return the byte[] of the decrypted data
   */
  public byte[] decrypt(byte[] data){
    return new byte[10];
  }
}