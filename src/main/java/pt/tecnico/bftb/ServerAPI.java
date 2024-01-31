package pt.tecnico.bftb;

import java.net.*;
import java.io.*;
import javax.crypto.*;
import java.security.*;
import java.util.Base64;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.security.cert.Certificate;
import java.security.KeyStore;
import java.time.Instant;
import java.nio.file.*;
import java.security.MessageDigest;


public class ServerAPI extends Thread
{
    private Socket              socket          = null;
    private ServerSocket        server          = null;
    private FileInputStream     logFile         = null;
    private FileInputStream     backupLogFile   = null;
    private ObjectInputStream   ois             = null;
    private FileOutputStream    copyFile        = null;
    private ObjectOutputStream  copyObject      = null;
    private boolean             corruptedFlag   = false;

    public ServerAPI(int port)
    {
        try
        {   
            System.out.println("Trying to initialize port " + port);
            server = new ServerSocket(port);
            Operations operationMethods = new Operations();
            Server serverOps = new Server();
            try {
                this.logFile = new FileInputStream("log.txt");
                this.ois = new ObjectInputStream(this.logFile);
                operationMethods = (Operations)ois.readObject();
                System.out.println("LOADED LOG FILE");
            } catch (Exception e) {
                corruptedFlag = true;
                System.out.println("Log file not found - created one");
            }
            try {
                this.backupLogFile = new FileInputStream("backupLog.txt");
                if (corruptedFlag == true) {
                    this.ois = new ObjectInputStream(this.backupLogFile);
                    operationMethods = (Operations)ois.readObject();
                    System.out.println("Main log was corrupted.");
                    copyFile = new FileOutputStream("log.txt");
                    copyObject = new ObjectOutputStream(copyFile);
                    copyObject.writeObject(operationMethods);
                    copyFile.close();
                }
                System.out.println("LOADED BACKUP LOG FILE");
            } catch (Exception e) {
                System.out.println(e);
                System.out.println("Backup log file not found - created one");
            }
            System.out.println("Server on");
            while(true) {
                try {
                    socket = server.accept();
                    Thread st = null;
                    if (port == 5000) {
                        st = new ServerThread(socket, operationMethods, serverOps, "serveralias");
                    } else if (port == 5001) {
                        st = new ServerThread(socket, operationMethods, serverOps, "serveralias1");
                    } else if (port == 5002) {
                        st = new ServerThread(socket, operationMethods, serverOps, "alias5");
                    } else if (port == 5003) {
                        st = new ServerThread(socket, operationMethods, serverOps, "alias4");
                    }
                    st.start();
                } catch (Exception e) {
                    System.out.println(e);
                }
            }
        }
        catch(IOException i)
        {
            System.out.println(i);
        }
    }

    public static void main(String args[])
    {
        new ServerAPI(Integer.valueOf((args[0])));
    }
}

class ServerThread extends Thread {

    private Socket                      socket                  = null;
    private DataInputStream             in                      = null;
    private DataOutputStream            out                     = null;
    private Operations                  operationMethods        = null;
    private ObjectOutputStream          oos, backupOos          = null;
    private String                      serverAlias             = null;
    private KeyStore.PrivateKeyEntry    serverPvk               = null;
    private PublicKey                   serverPbk               = null;
    private KeyStore                    ks                      = null;
    private FileOutputStream            file, backupFileOutput  = null;
    private Server                      serverOps               = null;
    private String                      serverPass              = null;

    public ServerThread(Socket s, Operations ops, Server serverOps, String serverAlias) {
        this.socket = s;
        this.operationMethods = ops;
        this.serverOps = serverOps;
        this.serverAlias = serverAlias;
    }

    public void run() {
        try {
            in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            out = new DataOutputStream(socket.getOutputStream());
            file = new FileOutputStream("log.txt");
            backupFileOutput = new FileOutputStream("backupLog.txt");
            oos = new ObjectOutputStream(file);
            oos.writeObject(this.operationMethods);
            setupServerCredentials();
        } catch(Exception e) {
            System.out.println(e);
        }

        Integer operation = -1, parameter = -1;
        String response, signedString, encodedData = null;
        boolean isValidAccount, sigVerified, replay = false;
        PublicKey pb, backupPb = null;
        String[] splitString = null;
        String cliPb = null;
        try {
            cliPb = in.readUTF();
            if (this.operationMethods.getWTimestamp(toPublicKey(cliPb)) != null) {
                out.writeUTF(String.valueOf(this.operationMethods.getWTimestamp(toPublicKey(cliPb))) + "-yes");
            } else {
                out.writeUTF("0-no");
            }
        } catch (Exception e) {
            System.out.println("Error sending client's timestamp");
        }
        while (operation != 99)
        {
            try
            {
                response = in.readUTF();
                splitString = response.split(";");   
                operation = Integer.valueOf(splitString[0]); 
                String hashString = null;
                byte[] hash = null;
                try {
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    hashString = generateRandomString();
                    digest.update(hashString.getBytes("UTF-8"));
                    hash = digest.digest();
                } catch (Exception e) {
                    System.out.println("Problem generating hash to send to server");
                    e.printStackTrace();
                }
            
                switch(operation) {

                    case 0:
                        serverOps.registerAccount(operation, splitString, response, out, in, operationMethods, serverPvk, serverPbk, file, backupFileOutput, oos, backupOos);
                        break;
                    case 1:
                        serverOps.viewAccount(operation, splitString, response, out, in, operationMethods, serverPvk, serverPbk, hashString, hash);
                        break;
                    case 2:
                        serverOps.transferBalanceAccount(operation, splitString, response, out, in, operationMethods, serverPvk, serverPbk, file, backupFileOutput, oos, backupOos, hashString, hash);
                        break;
                    case 3:
                        serverOps.receiveBalanceAccount(operation, splitString, response, out, in, operationMethods, serverPvk, serverPbk, file, backupFileOutput, oos, backupOos, hashString, hash);
                        break;
                    case 4:
                        serverOps.auditAccount(operation, splitString, response, out, in, operationMethods, serverPvk, serverPbk, hashString, hash);
                        break;
                    case 5:
                        try {
                            socket.close();
                            in.close();
                            out.close();
                            oos.close();
                            file.close();
                        } catch (IOException e) {
                            System.out.println(e);
                        }
                        System.exit(0);
                    default:
                        break;
                }

            }
            catch(IOException i)
            {
                System.out.println("IO Exception in API call.");
                break;
            }
        }
        try {
            socket.close();
            in.close();
            out.close();
            oos.close();
            file.close();
        } catch (IOException e) {
            System.out.println("Failure closing streams.");
        }
    }

    public String generateRandomString() {
        String alphaNumericString = "ABCDEFGH";
        StringBuilder sb = new StringBuilder(2);

        for (int i = 0; i < 6; i++) {
            int index = (int)(alphaNumericString.length() * Math.random());
            sb.append(alphaNumericString.charAt(index));
        }
        return sb.toString();
    }

    public void setupServerCredentials() {
        try {
            FileInputStream fis = new FileInputStream("bftbkeystore.jce");
            ks = KeyStore.getInstance("JCEKS");
            ks.load(fis, "password".toCharArray());
            fis.close();
            if (this.serverAlias.equals("serveralias")) {
                this.serverPass = "serverpass";
            } else if (serverAlias.equals("serveralias1")) {
                this.serverPass = "serverpass1";
            } else if (serverAlias.equals("alias5")) {
                this.serverPass = "password5";
            } else if (serverAlias.equals("alias4")) {
                this.serverPass = "password4";
            }
            serverPvk = (KeyStore.PrivateKeyEntry)ks.getEntry(serverAlias, new KeyStore.PasswordProtection(this.serverPass.toCharArray()));
            serverPbk = getPublicKey(this.serverAlias);
        } catch (Exception e) {
            System.out.println("Server credential generation failed.");
        }
    }

    public PublicKey getPublicKey(String alias) {
        PublicKey getPk = null;
        Certificate cert = null;
        try {
            cert = ks.getCertificate(alias);
            getPk = cert.getPublicKey();
            
        } catch(Exception e) {
            System.out.println("Failure retrieving public key.");
        }
        return getPk;
    }

    public PublicKey toPublicKey(String encodedData) {
        PublicKey pb = null;
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            pb = factory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(encodedData)));
        } catch(Exception e) {
            System.out.println(e);
        }
        return pb;
    }

}