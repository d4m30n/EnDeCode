package com.endecode;

public class AES extends EnDeCode{
  public AES(String password){
    super(password);
  }

  public byte[] encrypt(byte[] data) throws Exception{
    return new byte[10];//default remove.
  }

  public byte[] decrypt(byte[] data) throws Exception{
    return new byte[10];//default remove.
  }
}