package FinalProjectClient;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
/**
 * This class handles the general login formatting through a Gui.
 * @author liamtwomey
 */
public class loginGui extends JFrame {
    private JButton login, adduser;
    private JPanel loginpanel;
    private static JTextField fielduser, fieldpass, port, ip;
    private static JLabel username, serverl, portl, ipl;
    private JLabel password;
    private String usernamestring;
    private String passw;
    private String[] fieldnames2 = {"user", "password"}; 
    private String f2name = "users.db";
    private int choice = 0;
    private static String ipGlobal;
    private static String portGlobal ;
    private static String userGlobal ;
    private static String passGlobal ;
    private IvParameterSpec iv;
    /**
     * This is the gui that handles login operations to the password safe.
     * 
     */
     public loginGui() {
        
        super("Login");

        //this.userDB = new FlatDatabase(); 
        //openDB();
        login = new JButton("Login");
        adduser = new JButton("Create New User");
        loginpanel = new JPanel();
        fielduser = new JTextField(15);
        fieldpass = new JPasswordField(15);
        port = new JTextField(15);
        ip = new JTextField(15);
        username = new JLabel("Username: ");
        password = new JLabel("Password: ");
        serverl = new JLabel("Server Connection");
        portl = new JLabel("Port: ");
        ipl = new JLabel("IP: ");
        setSize(300, 200);
        setLocation(500, 280);
        loginpanel.setLayout(null);
        fielduser.setBounds(90, 30, 150, 20);
        fieldpass.setBounds(90, 65, 150, 20);
        login.setBounds(110, 210, 80, 20);
        username.setBounds(20, 28, 80, 20);
        password.setBounds(20, 63, 80, 20);
        adduser.setBounds(60, 250, 180, 20);
        serverl.setBounds(90, 100, 180, 20);
        portl.setBounds(20, 130, 180, 20);
        ipl.setBounds(20, 160, 180, 20);
        port.setBounds(90, 130, 150, 20);
        ip.setBounds(90, 160, 150, 20);
        loginpanel.add(login);
        loginpanel.add(fielduser);
        loginpanel.add(fieldpass);
        loginpanel.add(username);
        loginpanel.add(password);
        loginpanel.add(adduser);
        loginpanel.add(serverl);
        loginpanel.add(portl);
        loginpanel.add(ipl);
        loginpanel.add(port);
        loginpanel.add(ip);
        getContentPane().add(loginpanel);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setVisible(true);

        //action listener for login button

        login.addActionListener(new ActionListener() { //if the user already exists and is attempting to login
            public void actionPerformed(ActionEvent e) {
                if(fielduser.getText().equals("") || fieldpass.getText().equals("")
                        || port.getText().equals("") || ip.getText().equals(""))
                {
                    JOptionPane.showMessageDialog(null, "You must fill out all fields to login");
                }
                else
                {
                    userGlobal = fielduser.getText();
                    System.out.println(userGlobal);
                    passGlobal = fieldpass.getText();
                    System.out.println(passGlobal);
                    choice = 2;
                    validate();
                    String newiv = genIV();
                    Client C; //create an instance of the client object
                    try {
                        C = new Client(userGlobal, passGlobal, ip.getText(), port.getText(),2, newiv);
                        C.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                        C.setSize(900, 540); 
                        C.setVisible(true);
                    } catch (NoSuchAlgorithmException ex) {
                        Logger.getLogger(loginGui.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (InvalidKeySpecException ex) {
                        Logger.getLogger(loginGui.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
                
            }
        });

        adduser.addActionListener(new ActionListener() { //if you are adding a new user
            public void actionPerformed(ActionEvent e) {
                if(port.getText().equals("") || ip.getText().equals(""))
                {
                    JOptionPane.showMessageDialog(null, "You must enter a port and ip");
                }
                else
                {
                    JFrame webframe = new JFrame();   
                    userGlobal = JOptionPane.showInputDialog(webframe,"Enter New Username"); 
                    JFrame passframe = new JFrame();
                    passGlobal = JOptionPane.showInputDialog(passframe, "Enter New Password");
                    String newiv = genIV();
                    Client C; //create an instance of the client object
                    try {
                        C = new Client(userGlobal, passGlobal, ip.getText(), port.getText(),1, newiv);
                          C.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                        C.setSize(300, 300); 
                        C.setVisible(false);
                    } catch (NoSuchAlgorithmException ex) {
                        Logger.getLogger(loginGui.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (InvalidKeySpecException ex) {
                        Logger.getLogger(loginGui.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            }
        });
    }
     /**
      *  This method generates an new IV for every unique user that will be used throughout
      * their connection to the server as part of the session key.
      * @return the new iv as a base 64 string
      */
     public String genIV()
     {
        SecureRandom rand = new SecureRandom();
        byte[] rawIV = new byte[16];
        rand.nextBytes(rawIV);
        iv = new IvParameterSpec(rawIV);
        String ivString = Base64.getEncoder().encodeToString(iv.getIV());
        return ivString;
     }
}
