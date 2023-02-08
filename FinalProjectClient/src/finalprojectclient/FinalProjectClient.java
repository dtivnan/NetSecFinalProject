
package FinalProjectClient;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.UnknownHostException;
import java.util.Scanner;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.Box;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;

/**
 * this class instantiates the login gui
 * @author liamtwomey
 */
public class FinalProjectClient extends JFrame{

    /**
     * this method creates an instance of the login gui
     * @param args the command line arguments
     */
    static final int PORT_NUM = 5000;
    public static void main(String[] args) {
        
        loginGui gui = new loginGui();
        gui.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        gui.setSize(300, 300); 
        gui.setVisible(true);
        }

}