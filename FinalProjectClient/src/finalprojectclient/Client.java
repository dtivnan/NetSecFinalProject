
package FinalProjectClient;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *  This class handles all of the client-side operations as well as housing the 
 * gui that gives the password safe its functions.
 * @author liamtwomey
 */

public class Client extends JFrame{
    /**
     * this method handles connecting to the server as well as sending the initial
     * message to the server and receiving the servers response.
     * @param args the command line arguments
     */
    static int PORT_NUM;
    private static String username;
    private static String password;
    private static String ip;
    private static String port;
    private static String ivString;
    private static IvParameterSpec iv;
    private static int choice;
    private JButton add;
    private JPanel loginpanel;
    private JTextField fieldweb;
    private JTextField fielduser;
    private JTextField fieldpass;
    private JButton lookup;
    private JLabel website;
    private JLabel usernamef;
    private JLabel passwordf;
    private PrintWriter send = null;
    private Scanner recv = null;
    private String info = "";
    private SecretKey key;
    private byte[] rawIV = new byte[16];
    private int COST = 2048;        
    private int BLK_SIZE = 8;
    private int PARALLELIZATION = 1;  
    private int KEY_SIZE=128;
    /**
     * 
     * @param user
     * @param pass
     * @param ip
     * @param port
     * @param choice
     * @param ivString
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    public Client(String user, String pass, String ip, String port, int choice, String ivString) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        super("Password Safe");
        Security.addProvider(new BouncyCastleProvider());
        username = user;
        password = pass;
        this.ip = ip;
        this.port = port;
        PORT_NUM = Integer.parseInt(port);
        this.choice = choice;
        this.ivString = ivString;
        derive(password);
        add = new JButton("Add");
        loginpanel = new JPanel();
        fieldweb = new JTextField(15);
        fielduser = new JTextField(15);
        fieldpass = new JPasswordField(15);
        lookup = new JButton("Lookup");
        website = new JLabel("Website: ");
        usernamef = new JLabel("Username: ");
        passwordf = new JLabel("Password: ");
        setSize(300, 300);
        setLocation(500, 280);
        loginpanel.setLayout(null);
        fieldweb.setBounds(90, 37, 150, 20);
        fielduser.setBounds(90, 70, 150, 20);
        fieldpass.setBounds(90, 105, 150, 20);
        add.setBounds(110, 150, 80, 20);
        lookup.setBounds(95, 200, 110, 20);
        website.setBounds(20, 33, 80, 20);
        usernamef.setBounds(20, 68, 80, 20);
        passwordf.setBounds(20, 103, 80, 20);
        loginpanel.add(add);
        loginpanel.add(fieldweb);
        loginpanel.add(fielduser);
        loginpanel.add(fieldpass);
        loginpanel.add(lookup);
        loginpanel.add(website);
        loginpanel.add(usernamef);
        loginpanel.add(passwordf);
        getContentPane().add(loginpanel);
        Scanner scan = new Scanner(System.in);
        SSLSocketFactory fac;
        SSLSocket sock = null;
   
        // Set up the trust store.
        System.setProperty("javax.net.ssl.trustStore", "mytruststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "password");        
        try
        {
      // Set up a connection to the echo server running on the same machine
      // using SSL.
            fac = (SSLSocketFactory)SSLSocketFactory.getDefault();
            sock = (SSLSocket)fac.createSocket(ip, PORT_NUM);
            sock.startHandshake();
      // Set up the streams for the socket.
            this.recv = new Scanner(sock.getInputStream());
            this.send = new PrintWriter(sock.getOutputStream(), true);
        }
        catch(UnknownHostException ex)
        {
            System.out.println("Host is unknown.");
        }
        catch(IOException ioe)
        {
            ioe.printStackTrace();
        }
                lookup.addActionListener(new ActionListener() { // the action listener for the button to lookup info in the password safe
                @Override
                public void actionPerformed(ActionEvent e) {
                    String x = fielduser.getText();
                    String y = JOptionPane.showInputDialog(null, "Please enter the website you wish to lookup");
                    String infoT = x + ":" + y;
                    try {
                        //function call then add lookup
                         infoT = encrypt(infoT); //try to encrpyt the necessary info before sending to the server
                    } catch (NoSuchAlgorithmException ex) {
                        Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (NoSuchPaddingException ex) {
                        Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (InvalidKeyException ex) {
                        Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (InvalidAlgorithmParameterException ex) {
                        Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (IllegalBlockSizeException ex) {
                        Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (BadPaddingException ex) {
                        Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    infoT = "LOOKUP:" + infoT;// add lookup after its encrypted
                    Random r = new Random();
                    int ran = r.nextInt();
                    infoT= infoT + ":" + ran;//add a nonce for freshness
                    try {
                        send(infoT); //send to server
                    } catch (IOException ex) {
                        Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (NoSuchAlgorithmException ex) {
                        Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (NoSuchPaddingException ex) {
                        Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (InvalidKeyException ex) {
                        Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (InvalidAlgorithmParameterException ex) {
                        Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (IllegalBlockSizeException ex) {
                        Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (BadPaddingException ex) {
                        Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            });
                add.addActionListener(new ActionListener() {// the action listener for the button to add a new entry to the password safe
            @Override
            public void actionPerformed(ActionEvent e) {
                String x = fielduser.getText();
                String b = fieldweb.getText();
                String z = fieldpass.getText();
                if(x.equals("") || b.equals("") || z.equals("")) //if the fields are empty
                {
                    JOptionPane.showMessageDialog(null, "You must fill out all fields");
                }
                else
                {
                String infoT = "";
                infoT = x + ":" + b + ":" + z;
                try {
                    infoT = encrypt(infoT);
                    infoT = "ADD:" + infoT;
                    Random r = new Random(); //add a nonce for freshness
                    int ran = r.nextInt();
                    infoT = infoT + ":" + ran;
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchPaddingException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InvalidKeyException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InvalidAlgorithmParameterException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IllegalBlockSizeException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                } catch (BadPaddingException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                }
                try {
                    send(infoT); //send the info
                } catch (IOException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchPaddingException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InvalidKeyException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InvalidAlgorithmParameterException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IllegalBlockSizeException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                } catch (BadPaddingException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            }
        });

        if(choice == 1)// if the user is enrolling
        {
            info = username +":"+password;
            info = "CREATE:"+info + ":" + Base64.getEncoder().encodeToString(iv.getIV());//with the user iv
        }
        else
        {
            info = username +":"+password;
            String code = JOptionPane.showInputDialog(null,"Enter your 6 digit code"); //the otp
            info = "AUTH:" + info + ":" + code; //if they are want to authenticate
            //add auth to the string
        }
    // Send the message to the server.
        send.println(info);
        info ="";
        send.flush();
        // Echo the response to the screen.
        String recvMsg = recv.nextLine();
        
         //print out the message incase they cannot copy from joption pane
        if(recvMsg.equals("NOK"))
        {
            JOptionPane.showMessageDialog(null, "You either already exist in the database or"
                    + "you failed to login");
        }
        else 
        {
            if(recvMsg.contains(" ")) // if the user is already in the database
            {
                String[] split = recvMsg.split(" ");
                ivString = split[1];
                iv = new IvParameterSpec(ivString.getBytes());           
            }
            else // if the user just entered the database
            {
                this.setVisible(false);
                String[] split = recvMsg.split(":"); //display the secret for creating the otp
                String key = split[1];
                JOptionPane.showMessageDialog(null, "Use this string to create a"
                    + "QR code to generate one time passwords with the link: https://freeotp.github.io/qrcode.html \n"
                    + "String :" + key);
                System.out.println(key);
            }
        }        
        try
        {
      // Close the connection.
            sock.close();
        }
        catch(IOException ioe)
        {
      // Gulp! Swallow this exception, we're exiting anyway.
        }      
    }
    /**
     * This method is essentially a broken down copy of the constructor for this class.
     * This method creates a connection to the server and sends whatever info needs to be
     * sent. It also receives the response from the server and dictates how to 
     * handle the response and what actions need to be taken.
     * @param mess the info to be sent to the server
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws AEADBadTagException 
     */
    public void send(String mess) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, AEADBadTagException
    {
        SSLSocketFactory fac;
        SSLSocket sock = null;
        send.println(mess);
        System.setProperty("javax.net.ssl.trustStore", "mytruststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "password");
        Scanner scan = new Scanner(System.in);
        fac = (SSLSocketFactory)SSLSocketFactory.getDefault();
        sock = (SSLSocket)fac.createSocket("127.0.0.1", PORT_NUM);
        sock.startHandshake();
        PrintWriter send = new PrintWriter(sock.getOutputStream(), true);
        Scanner recv = new Scanner(sock.getInputStream());
        send.println(mess);     
        String info = recv.nextLine();
        if(info.equals("NOK"))
        {
            JOptionPane.showMessageDialog(null, "That record either already exists or does not exist at all");
        }
        else if(info.equals("OK"))
        {
            JOptionPane.showMessageDialog(null, "Successfully added");
        }
        else //if they user is receiving back info from the safe
        {
            String[] dec = info.split(":");
            String pass = decrypt(dec[1]);
            JOptionPane.showMessageDialog(null, "website: " + dec[0] +"\npassword: " + pass);
        }
    }
    /**
     * this method derives the Scrypt key that is used for the encryption
     * of data sent between the client and server.
     * @param password the current users password that will create the key
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    public void derive(String password) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        Security.addProvider(new BouncyCastleProvider());
        SecretKeyFactory factory = SecretKeyFactory.getInstance("SCRYPT");
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(rawIV);
        ScryptKeySpec scryptSpec = new ScryptKeySpec(password.toCharArray(),rawIV, COST, BLK_SIZE,
        PARALLELIZATION, KEY_SIZE);
        iv = new IvParameterSpec(rawIV);
        key = SecretKeyFactory.getInstance("SCRYPT").generateSecret(
        scryptSpec);
    }
    /**
     * This method ecrypts data using AES/GCM/NoPadding before it is sent to 
     * the server where it is added to the password safe. The method handles
     * two cases, if the user is looking up data or if the user is adding data 
     * to the password safe. If the user is looking up only the website name and
     * user name are necessary, however for adding a password is also needed
     * @param message the message to be encrypted
     * @return the encrypted message
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public String encrypt(String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        String[] array = message.split(":");
        if(array.length == 2)// if they are looking up 
        {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); //encrypt the password
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] ctext = cipher.doFinal(array[0].getBytes()); //encrypt
            String mess = Base64.getEncoder().encodeToString(ctext);
            mess = mess + ":";
            mess = mess + array[1]; //concatonate so it is one string seperated with a colon
            return mess;
        }
        else// if the user is adding to the safe
        {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); //encrypt the password
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] ctext = cipher.doFinal(array[0].getBytes());
            cipher = Cipher.getInstance("AES/GCM/NoPadding"); //encrypt the data 
            cipher.init(Cipher.ENCRYPT_MODE, key , iv);
            cipher = Cipher.getInstance("AES/GCM/NoPadding"); //encrypt data 
            cipher.init(Cipher.ENCRYPT_MODE, key , iv);
            byte[] ctext2 = cipher.doFinal(array[2].getBytes());
            String mess = Base64.getEncoder().encodeToString(ctext);
            mess = mess + ":" + array[1] +
                    ":" + Base64.getEncoder().encodeToString(ctext2); //concatonate int one string
            return mess;  //return the string
        } 
    }
    /**
     * this message decrypts some message after it is received from the server
     * using the key and IV that are associated with the current user.
     * @param message the message to decrypt
     * @return the decrypted string
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws AEADBadTagException 
     */
    public String decrypt(String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, AEADBadTagException
    {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plaintext = null;
        try{
         plaintext = cipher.doFinal(Base64.getDecoder().decode(message));// decrypt
        }
        catch(AEADBadTagException ex){
            
        }
        return new String(plaintext);
    }

}
