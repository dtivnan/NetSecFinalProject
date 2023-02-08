
package FinalProjectServer;

import csc5055.Base32;
import csc5055.flatdb.FlatDatabase;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.net.ssl.SSLServerSocketFactory;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import csc5055.flatdb.Record;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;

/**
 * This class handles the server-side operations as well as 
 * manages both the user and password safe databases.
 * @author liamtwomey
 */
public class FinalProjectServer {

    static final int PORT_NUM = 5000;
    private static FlatDatabase passBase;
    private static final String dbName = "passBase.db";
    private final static String [] fields = {"username", "password", "iv", "HMAC_key", "personalIV"};
    private static final int COST = 2048;          // A.K.A Iterations
    private static final int BLK_SIZE = 8;
    private static final int PARALLELIZATION = 1;
    private static final int KEY_SIZE=128;
    private static String IV = null;
    private static String ivString = "";
    private static String hashString = "";
    private static String username = "";
    private static String password = "";  
    private static FlatDatabase passWordSafe;
    private static final String psName = "safe.db";
    private static final String[] dbFields = {"website"};
    private static final String [] safeFields  = { "username", "website", "password"};
    
    /**
     * This is the main method which handles sending and receiving messages
     * to and from the client.
     * @param args the command line argument
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException 
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException 
    {
        Security.addProvider(new BouncyCastleProvider());
        SSLServerSocketFactory sslFact;
        ServerSocket server;
        passBase = new FlatDatabase();//make a database object
        passWordSafe = new FlatDatabase();
        openandCreate(); //opne the database
   // Set the keystore and keystore password.
        System.setProperty("javax.net.ssl.keyStore", "mykeystore.jks"); //use my keystore
        System.setProperty("javax.net.ssl.keyStorePassword", "password");
        String hmac_key = "";
        String confirmation = "";
        String current_nonce;
        String past_nonce = "0";

        try
        {
     // Get a copy of the deafult factory. This is what ever the
     // configured provider gives.
             sslFact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
     // Set up the server socket using the specified port number.
            server = sslFact.createServerSocket(PORT_NUM);
     // Loop forever handing connections.
            while (true)
        {
       // Wait for a connection.
            Socket sock = server.accept();

            System.out.println("Connection received.");
       // Setup the streams for use.
            Scanner recv = new Scanner(sock.getInputStream());
            PrintWriter send = new PrintWriter(sock.getOutputStream(), true);
       // Get the line from the client.
            String line = recv.nextLine();
            String [] fullLine = line.split(":");
            if(fullLine[0].equals("CREATE")) //if they are onrolling
            {
                username = fullLine[1];
                password = fullLine[2]; 
                String personalIV = fullLine[3];
                byte[] hash = hash(fullLine[2]); //hash the password
                password = Base64.getEncoder().encodeToString(hash);
                hmac_key = hmac(); //get the hmac key
                hmac_key = Base32.encodeToString(hmac_key.getBytes(), true);
                confirmation = insertRecord(username, password, IV, hmac_key, personalIV);//confirm if it is        
                if(confirmation == "OK")
                {
                    send.println(confirmation + ":" + hmac_key);// if it is send the confirmation and hmac
                    send.flush();
                }
                else{
                    send.println("NOK");// if it doens't add 
                    send.flush();}
            }
            else if(fullLine[0].equals("AUTH")) //if they are authenticating a user
            {
                username = fullLine[1];
                password = fullLine[2]; 
                if(lookupRecord(username, password)) //look up the current user
                {  
                    Record r;
                    if((r = passBase.lookupRecord("username", username)) == null)
                        send.println("NOK");   
                    String sKey = r.getFieldValue("HMAC_key");
                    String iv = r.getFieldValue("personalIV");
                    String onetime = fullLine[3];
                    byte[] nkey = Base32.decode(sKey);
                    sKey = Base64.getEncoder().encodeToString(nkey);
                    OTP otp = new OTP(0,sKey);
                    if(otp.verify(onetime))
                        send.println("OK:" + " "+ iv);//if it authenticates
                    else
                        send.println("NOK");
                   send.flush();
                }
                else
                    send.println("NOK+1"); //if it doenst
                send.flush();
            }  
            else if(fullLine[0].equals("LOOKUP"))// if they are attempting to lookup in the password safe
                {
                    if(past_nonce.equals("0")) //check the nonce to avoid replays
                    {
                        past_nonce = fullLine[3];
                        current_nonce = fullLine[3];
                        confirmation = lookupSafe(fullLine[1], fullLine[2]); //retrieve info from the database
                    }
                    else
                    {
                        current_nonce = fullLine[3];
                        if(current_nonce.equals(past_nonce)) //check the nonce to avoid replays
                        {
                            confirmation = "NOK";
                        }
                        else
                        {
                            confirmation = lookupSafe(fullLine[1], fullLine[2]);//retrieve info from the database
                        }
                        
                    }
                    send.println(confirmation);
                }
           else if(fullLine[0].equals("ADD"))// if they are adding to the password safe
                {
                    if(past_nonce.equals("0")) //check the nonce to avoid replays
                    {
                        past_nonce = fullLine[4];
                        current_nonce = fullLine[4];
                        confirmation = safeInsert(fullLine[1],fullLine[2],fullLine[3]);//insert into the safe
                    }
                    else
                    {
                        current_nonce = fullLine[4];
                        if(current_nonce.equals(past_nonce))
                        {
                            confirmation = "NOK";
                        }
                        else
                        {
                            confirmation = safeInsert(fullLine[1],fullLine[2],fullLine[3]);//insert into the safe
                        }
                    }
                    send.println(confirmation);
                }
       // Echo the line back 
       // Close the connection.
            sock.close();
            }
        }
        catch(IOException ioe)
        {
            ioe.printStackTrace();
        }
   }//end of main
    /**
     * this method creates a new database or opens and existing one depending 
     * on whether or not one already exists.
     */
    public static void openandCreate()
    {
        if(passBase.createDatabase(dbName, fields))//create a database
        {
        }
        else
            passBase.openDatabase(dbName); //open an existing one if you can't create
        
        if(passWordSafe.createDatabase(psName, dbFields))
        {
        }
        else
            passWordSafe.openDatabase(psName);
    }//end of openAndCreate
    
    /**
     * this method hashes the users password using SCRYPT and returns the hashed
     * password as a byte array
     * @param message the users unhashed password
     * @return a byte array containing the hashed password
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    public static byte[] hash(String message) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        SecureRandom rand;               // A secure random number generator.
        byte[] rawIV = new byte[16];  
        rand = new SecureRandom();
        rand.nextBytes(rawIV);
        IvParameterSpec iv = new IvParameterSpec(rawIV);       
        IV = Base64.getEncoder().encodeToString(iv.getIV());
        SecretKeyFactory skf = SecretKeyFactory.getInstance("SCRYPT");
        ScryptKeySpec spec = new ScryptKeySpec(message.toCharArray(),
                    rawIV, COST, BLK_SIZE, PARALLELIZATION, KEY_SIZE);
        byte [] hash = skf.generateSecret(spec).getEncoded();//hash the password
        return hash;   
    }//end of hash
    
    /**
     * This method creates the HMAC SHA1 key
     * @return the base32 string that is the key
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException 
     */
    public static String hmac() throws NoSuchAlgorithmException, InvalidKeyException
    {
        String s = "";
        SecretKey key;
        byte[] tag;
        Mac hmac = Mac.getInstance("HmacSHA1");//make it HMAC SHA1 instance
        KeyGenerator hmacKeyGen = KeyGenerator.getInstance("HmacSHA1");
        key = hmacKeyGen.generateKey();
        hmac.init(key);
        s = Base32.encodeToString(key.getEncoded(), true);//turn it into a string
        return s;
    }
    
    /**
     * This method creates a new record object and inserts it into the 
     * flatdatabase object.
     * @param username the current username
     * @param password the current password
     * @param iv the current iv
     * @param hmac the current hmac key
     * @return a string that represents whether or not insertion was sucessful
     */
    public static String insertRecord(String username, String password, String iv, String hmac, String personalIV)
    {
        String fieldVals[] = {username, password, iv, hmac, personalIV};
        String s = "";
        Record r = new Record(fields, fieldVals);
        if(passBase.insertRecord(r))
        {
            if(passBase.saveDatabase())
                s = "OK";
        }
        else
        {
            s = "NOK";
        }
        String hash = r.getFieldValue("HMAC_key");

            return s;
    }
    /**
     * This method inserts a record into the flatdatabase that makes up the 
     * password safe
     * @param user the username for a specific website to add to the sage
     * @param website the specific website
     * @param pass the corresponding password
     * @return OK if it is added NOK if it fails
     */
    public static String safeInsert(String user, String website, String pass)
    {
        String fields[] = { user, website, pass};
        Record r = new Record(safeFields, fields);
        String s = "";
        if(passWordSafe.insertRecord(r))
        {
            if(passBase.saveDatabase())
                s = "OK";
        }
        else
        {
            s = "NOK";
        }
        return s;
    }
    /**
     * this method looks up a record in the flatdatabase in order to authenticate
     * a current user.
     * @param user the current user
     * @param password the current users password
     * @return true if the passwords match
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    public static boolean lookupRecord(String user, String password) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        Record r = new Record(fields, fields);
        r = passBase.lookupRecord("username", user);
        String hP = r.getFieldValue("password");
        String iv = r.getFieldValue("iv");
        if(hashAndMatch(iv, password, hP))//hash and match the new password
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    /**
     * This method takes specific information and looks up a record that 
     * corresponds to the info.
     * @param user the username for the website
     * @param website the specific website
     * @return the website and password or NOK if failure
     */
    public static String lookupSafe(String user, String website)
    {
        Record r = new Record(safeFields);
        r = passWordSafe.lookupRecord("website", website);
        String tempU = r.getFieldValue("username");
        String tempW = r.getFieldValue("website");
        String tempP = "";
        String s = "";
        if(tempW.equals(website))
        {
            tempP = r.getFieldValue("password");
            s = tempW + ":" + tempP;
        }
        else
            s = "NOK";
        return s;
    }
    
    /**
     * This method hashes the current users password and compares it to the 
     * stored hashed password. if they match then the user is essentially
     * authenticated
     * @param iv the iv received from the record
     * @param password the current password
     * @param hashedPass the stored hashed password
     * @return true if the two passes match false if they dont
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    public static boolean hashAndMatch(String iv, String password, String hashedPass) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        byte[] salt = Base64.getDecoder().decode(iv);//turn the string back into a byte array
        SecretKeyFactory skf = SecretKeyFactory.getInstance("SCRYPT");
        ScryptKeySpec spec = new ScryptKeySpec(password.toCharArray(),
                    salt, COST, BLK_SIZE, PARALLELIZATION, KEY_SIZE);
        byte [] hash = skf.generateSecret(spec).getEncoded();
        String h = Base64.getEncoder().encodeToString(hash);
        if(h.equals(hashedPass))//compare the two passwords
        {
            return true;
        }
        else
        {
            return false;
        }
     }
}
