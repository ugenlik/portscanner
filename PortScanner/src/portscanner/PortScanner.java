/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package portscanner;

/**
 *
 * @author ugenlik1
 */


import java.io.*;
import java.net.*;
import java.nio.channels.DatagramChannel;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;


public class PortScanner {

    /**
     * @param args the command line arguments
     */
    
    
    
    int pWin = 0 , pUnix = 0, openTCP = 0, openUDP = 0;
    
    public static int[] unixPorts = {7, 9, 13, 22, 79, 512, 513, 514, 515, 517,
        518, 519, 520, 521,
        525, 526, 530, 531, 532, 540, 543, 544, 548, 556};
    public static int[] windowsPorts = {135, 137, 138, 139, 445};
    public static final String FILE_NAME = "log.txt";
    public static final int TIMEOUT_DEFAULT = 50;

    private int timeout;
    
    private PrintWriter log = null;
    
    boolean isWebServer = false;

    

    public void run() throws UnknownHostException, InterruptedException {

        // Get input from user
        Scanner stdin = new Scanner(System.in);
        System.out.print("Enter target host name or IP:");
        String hostname = stdin.nextLine();
        try {
            System.out.print("Enter connection timeout in ms.Default TimeOut is 50ms " +"["+ TIMEOUT_DEFAULT +"]: ");
            timeout = Integer.parseInt(stdin.nextLine());
        } catch (NumberFormatException e) {
            timeout = TIMEOUT_DEFAULT;
        }

        // Resolve host name
        InetAddress IP = Inet4Address.getByName(hostname);

        
        
        
        // Prepare log file
        File f = new File(FILE_NAME);
        f.delete();
        try {
            f.createNewFile();
            log = new PrintWriter(f);
        } catch (IOException ex) {
            System.out.println("Something wrong with the log file. " +
                    "Remove the log file before running and make sure you " +
                    "have permission to write onto disk.");
            System.exit(-1);
        }

        System.out.println("Starting scan on " + IP.getHostAddress() + "...");

        // TCP scan
        System.out.println("Open TCP ports:");
        for (int i = 1; i <= 1024; i++) {
            printPorts(i);
            String result = scanTCP(IP, i);
            appendLog("TCP", i, result);
            if (result.equals("OPEN")) {
                System.out.println("\rFound open TCP port: " + i);

                if (i == 80) {
                    isWebServer = true;
                }

                openTCP++;

                if (Arrays.binarySearch(windowsPorts, i) >= 0) {
                    pWin++;
                }
                if (Arrays.binarySearch(unixPorts, i) >= 0) {
                    pUnix++;
                }
            }
        }
        System.out.println();

        // UDP scan
        System.out.println("Open UDP ports:");
        for (int i = 1; i <= 1024; i++) {
            printPorts(i);
            String result = scanUDP(IP, i);
            appendLog("UDP", i, result);
            if (result.equals("OPEN")) {
                System.out.println("\rFound open UDP port: " + i);

                openUDP++;
            }
        }
        System.out.println();

        log.close();

        // Display results
        System.out.println("Number of open TCP ports: " + openTCP);
        System.out.println("Number of open UDP ports: " + openUDP);

        System.out.println("Number of open Windows-specific TCP ports: " + pWin);
        System.out.println("Number of open Unix-specific TCP ports: " + pUnix);

        if (pUnix == pWin) {
            System.out.println("Cannot determine the target OS based on open ports.");
        } else {
            String os = pUnix > pWin ? "Unix" : "Windows";
            System.out.println("Target is probably running " + os);
        }

        isWebServer = true;
        if (isWebServer) {
            System.out.println("Web server is running on target machine. "
                    + "Getting \"Server\" header.");
            try {
                // connect to web server
                Socket sock = new Socket(IP, 80);

                // make requset
                OutputStream out = sock.getOutputStream();
                PrintWriter pw = new PrintWriter(out);
                pw.print("GET / HTTP/1.0\n\n");
                pw.flush();

                // get response
                InputStream in = sock.getInputStream();
                InputStreamReader ir = new InputStreamReader(in);
                BufferedReader br = new BufferedReader(ir);
                Thread.sleep(2000);
                while (br.ready()) {
                    String header = br.readLine();
                    if (header.toLowerCase().startsWith("server")) {
                        System.out.println(header);
                        break;
                    }
                }
                in.close();
                sock.close();
            } catch (IOException ex) {
                System.out.println("Cannot connect to web server.");
            }
        }

        System.out.println("Check " + FILE_NAME + " for scan detailed report.");
    }

  
    
    
    // Main 
    
    public static void main(String[] args) throws UnknownHostException, InterruptedException, IOException {
        new PortScanner().run();
       
        
    }

    /**
     * Scans single port using specified TCP host/port
     * @return String - either OPEN CLOSED DROPPED
     * @param IP IP Address of target machine
     * @param port port number
     */
    public String scanTCP(InetAddress IP, int port) {
        Socket s = null;
        try {
            s = new Socket();

            //set the socket to timeout, multiply the timeout by number of retry
            s.connect(new InetSocketAddress(IP, port), timeout);
            
            return "OPEN";
        } catch (IOException e) {
            return "CLOSED";
        } finally {
            if (s != null) {
                try {
                    s.close();
                } catch (IOException ex) {
                }
            }
        }
    }

    /**
     * Scans single UDP port on host/port
     * @return String either OPEN CLOSED
     * @param IP IP address of target machine
     * @param port port number
     */
    protected String scanUDP(InetAddress IP, int port) throws InterruptedException {
        DatagramSocket ds;
        DatagramPacket dp;
        DatagramChannel dChannel;
        try {
            byte[] bytes = new byte[128];
            ds = new DatagramSocket();
            dp = new DatagramPacket(bytes, bytes.length, IP, port);
            dChannel = DatagramChannel.open();
            dChannel.connect(new InetSocketAddress(IP, port));
            dChannel.configureBlocking(true);
            ds = dChannel.socket();
            ds.setSoTimeout(timeout);
            ds.send(dp);
            dp = new DatagramPacket(bytes, bytes.length);
            Thread.sleep(timeout);
            ds.receive(dp);

            //check datagram channel still connected
            if (!dChannel.isConnected() || !dChannel.isOpen()) {
                ds.close();
                return "CLOSED";
            }

            ds.disconnect();
            dChannel.disconnect();
            dChannel.close();
            ds.close();
        } catch (IOException e) {
            return "CLOSED";
        }
        return "OPEN";
    }

    /**
     * Prints the port number on current line without line feed character
     * @param port port number
     */
    void printPorts(int port) {
        System.out.print("\r");
        for (int i = 0; i < 100; i++) {
            System.out.print(" ");
        }
        System.out.print("\rScanning port " + port + "...");
    }

    /**
     * Appends scan result of single port to the log file
     * @param protocol This should be "TCP" or "UDP"
     * @param port port number
     * @param status Status of the scanned port
     */
    public void appendLog(String protocol, int port, String status){
            final DateFormat dateFormat = new SimpleDateFormat("HH:mm:ss.SSS");
            log.println(dateFormat.format(new Date()) + "\t"+ protocol +"\t" + port + "\t" + status);
            log.flush();
    }
}




