import java.util.Random;

import com.endecode.AES;

public class main{

  public static final String alpherbet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  public static final int MAXSTRINGLENGTH = 200;

  public static void main(String args[]) throws Exception{
    AES aes = new AES("testing");
    Random rand = new Random();
    int i = 300;
    while(i > 0){
      i--;
      String encryptString = genString(rand,rand.nextInt(MAXSTRINGLENGTH+1));
      String returnedString = aes.encrypt(encryptString);
      String decryptedString = aes.decrypt(returnedString);
      System.out.println("Original: "+encryptString+"\nEncrypted: "+returnedString+"\nDecrypted: "+decryptedString+"\n\n");
      if(encryptString.compareTo(decryptedString) != 0) 
        throw new Exception("Two Strings are not valid\n"+encryptString+"\n"+decryptedString);
      else{
      }
    }
    System.out.println("All Tests Passed");
  }

  private static String genString(Random rand, int size){
    String returnString = "";
    while(size >= 0){
      size--;
      returnString += alpherbet.charAt(rand.nextInt(alpherbet.length()));
    }
    return returnString;
  }
}