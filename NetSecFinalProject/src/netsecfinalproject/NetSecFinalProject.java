
package netsecfinalproject;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.UnknownHostException;
import java.security.Security;
import java.util.Scanner;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.JOptionPane;

/**
 *
 * @author liamtwomey
 */
public class NetSecFinalProject {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        
        Scanner scan = new Scanner(System.in);
        SSLSocketFactory fac;
        SSLSocket sock = null;
        Scanner recv = null;
        PrintWriter send = null;
        String info = "";
        // Set up the trust store.
        System.setProperty("javax.net.ssl.trustStore", "mytruststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "password");
        
        try
        {
      // Set up a connection to the echo server running on the same machine
      // using SSL.
            fac = (SSLSocketFactory)SSLSocketFactory.getDefault();
            sock = (SSLSocket)fac.createSocket("127.0.0.1", 4999);
            sock.startHandshake();

      // Set up the streams for the socket.
            recv = new Scanner(sock.getInputStream());
            send = new PrintWriter(sock.getOutputStream(), true);
        }
        catch(UnknownHostException ex)
        {
            System.out.println("Host is unknown.");
            return;
        }
        catch(IOException ioe)
        {
            ioe.printStackTrace();
        }

    // Send the message to the server.
        Scanner in = new Scanner(System.in);
        System.out.println("type something in");
        info = in.next();
        send.println(info);

    // Echo the response to the screen.
        String recvMsg = recv.nextLine();
        System.out.println("Server Said: " + recvMsg);
        
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
    
}