package pt.tecnico.bftb;

import java.net.*;
import java.io.*;
import java.util.*;
import java.security.*;
import java.security.cert.Certificate;
import javax.crypto.*;
import java.security.KeyStore;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.security.MessageDigest;


public class Client
{
    private Socket                  socket         = null;
    private DataInputStream         input          = null;
    private DataInputStream         in             = null;
    private DataOutputStream        out            = null;
    private KeyPairGenerator        keyGen         = null;
    private SecureRandom            random         = null;
    private KeyPair                 pair           = null;
    private PrivateKey              privateKey     = null;
    private PublicKey               publicKey      = null;
    private KeyStore                ks             = null;
    private String                  alias          = null;
    private Signature               dsaForVerify   = null;
    private Signature               dsaForSign     = null;
    private List<String>            sigList        = new ArrayList<String>();
    private List<Socket>            serverSockets  = new ArrayList<Socket>();
    private List<DataInputStream>   serverInputs   = new ArrayList<DataInputStream>();
    private List<DataOutputStream>  serverOutputs  = new ArrayList<DataOutputStream>();
    private HashMap<String, ArrayList<Integer>> serverAddressesToPorts = new HashMap<String, ArrayList<Integer>>();
    private final Integer allowedFaults = 1;
    private Integer serverPort = 5000;
    private String terminalPassword = null;
    private String terminalAlias = null;
    private KeyStore.PrivateKeyEntry clientPrivateKey;
    private boolean registered = false;

    //Byzantine Fault Tolerance
    private Integer accountAliasToWTS = 0;
    private Integer accountAliasToRID = 0;

    public Client()
    {
        serverAddressesToPorts.put("127.0.0.1", new ArrayList<Integer>());
        for (int i = 0; i < 3 * this.allowedFaults + 1; i++) {
            serverAddressesToPorts.get("127.0.0.1").add(serverPort);
            this.serverPort += 1;
        }

        Scanner input = new Scanner(System.in);
        try {
            FileInputStream fis = new FileInputStream("bftbkeystore.jce");
            ks = KeyStore.getInstance("JCEKS");
            ks.load(fis, "password".toCharArray());
            fis.close();

        } catch (Exception e) {
            System.out.println("Problem loading keystore");
            System.exit(1);
        }
        try
        {
            for (Map.Entry<String, ArrayList<Integer>> entry : serverAddressesToPorts.entrySet()) {

                for(Integer port : entry.getValue()) {

                    socket = new Socket(entry.getKey(), port);
                    socket.setSoTimeout(5000);
                    serverSockets.add(socket);
                    System.out.println("Connected to address " + entry.getKey() + ", port " + port);
                    in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
                    out = new DataOutputStream(socket.getOutputStream());
                    serverInputs.add(in);
                    serverOutputs.add(out);
                }
            }

            // Multiple ports create sockets for those ports and in/outs
            
        }
        catch(Exception e)
        {
            System.out.println("Problem creating socket/streams in client.");
            System.exit(1);
        }

        Integer operation = -1;
        PublicKey clientAliasPB = null;
        byte[] byte_pub1 = null;

        System.out.println("Insert alias to take public key from:");

        if (!input.hasNext()) {
            System.out.println("Not a valid alias");
            input.nextLine();
            System.exit(1);
        }

        try {
            terminalAlias = input.nextLine();
            clientAliasPB = getPublicKey(terminalAlias);
            byte_pub1 = clientAliasPB.getEncoded();
        } catch (Exception e) {
            System.out.println("Not a valid alias");
            System.exit(1);
        }

        System.out.println("Insert private key password:");
        if (!input.hasNext()) {
            System.out.println("Not a valid password");
            input.nextLine();
            System.exit(1);
        }
        
        try {
            terminalPassword = input.nextLine();
            clientPrivateKey = (KeyStore.PrivateKeyEntry)ks.getEntry(terminalAlias, new KeyStore.PasswordProtection(terminalPassword.toCharArray()));
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
        sendSockets(Base64.getEncoder().encodeToString(clientAliasPB.getEncoded()));
        String[] initialize = readFromSockets().split("-");
        accountAliasToWTS = Integer.valueOf(initialize[0]);
        if (initialize[1].equals("yes")) {
            registered = true;
        }

        while (operation != 99)
        {
            try
            {  
                String                      response, chosenAlias, outgoingAlias, password = "";
                byte[]                      byte_pub                        = null;
                PublicKey                   destPk                          = null;
                Integer                     balance                         = -1, index = -1, iter = 0;
                KeyStore.PrivateKeyEntry    pk                              = null;
                String                      toSign, signatureResponse,correctHash       = null;
                byte[]                      signature                       = null;
                Long                        timestamp                       = null;
                String[]                    splitString                     = null,hashes = null,hashesToSend = null;
                boolean                     sigVerified                     = false;
                MessageDigest               digest                          = null;
                
                printTable();
                if (input.hasNextInt()) {
                    operation = input.nextInt();
                    input.nextLine();
                    if (operation < 0 || operation > 5) {
                        System.out.println("Not a valid operation");
                        continue;
                    }
                } else {
                    System.out.println(input.nextLine());
                    operation = -1;
                }
                
                try {
                    dsaForSign = Signature.getInstance("SHA256withRSA");
                    dsaForVerify = Signature.getInstance("SHA256withRSA");
                } catch (Exception e) {
                    System.out.println("Problem getting signatures");
                    System.exit(1);
                }
                switch(operation) {

                    //open_account
                    case 0:

                        incrementWTS();

                        signature = "signature".getBytes();
                        toSign = operation + ";" + Base64.getEncoder().encodeToString(clientAliasPB.getEncoded()) + ";" + System.currentTimeMillis();
                        signature = signatureSetup(clientPrivateKey, toSign, signature, dsaForSign);
                        sendSockets(toSign);
                        sendSockets(Base64.getEncoder().encodeToString(signature));                        

                        response = readAndVerifySockets();
                        if (response.equals("Couldn't reach a consensus. Exiting.")) {
                            System.out.println("Couldn't reach a consensus. Exiting.");
                            decrementWTS();
                            break;
                        }
                        System.out.println(response);
                        registered = true;
                        break;

                    //check_account
                    case 1:
                        if (registered == false) {
                            System.out.println("Please register yourself first");
                            break;
                        }

                        incrementWTS();

                        System.out.println("Insert account to view:");

                        if (!input.hasNext()) {
                            System.out.println("Not a valid alias");
                            input.nextLine();
                            decrementWTS();
                            break;
                        }

                        try {
                            alias = input.nextLine();
                            publicKey = getPublicKey(alias);
                            byte_pub = publicKey.getEncoded();
                        } catch (Exception e) {
                            System.out.println("There is no such alias");
                            decrementWTS();
                            break;
                        }

                        signature = "signature".getBytes();
                        toSign = operation + ";" + Base64.getEncoder().encodeToString(clientAliasPB.getEncoded()) + ";" + System.currentTimeMillis() + ";" + Base64.getEncoder().encodeToString(publicKey.getEncoded());
                        signature = signatureSetup(clientPrivateKey, toSign, signature, dsaForSign);
                        sendSockets(toSign);
                        sendSockets(Base64.getEncoder().encodeToString(signature));
                        hashes = votelessReadFromSockets();
                        hashesToSend = new String[4];
                        digest = MessageDigest.getInstance("SHA-256");
                        iter = 0;
                        while (true) {
                            if (iter == 4) {
                                    break;
                                }
                            correctHash = generateRandomString();
                            digest.update(correctHash.getBytes("UTF-8"));
                            if (Base64.getEncoder().encodeToString(digest.digest()).equals(hashes[iter])) {
                                hashesToSend[iter] = correctHash;
                                iter++;
                            }
                        }
                        sendHashSockets(hashesToSend, signature);

                        response = readAndVerifySockets();
                        if (response.equals("Couldn't reach a consensus. Exiting.")) {
                            System.out.println("Couldn't reach a consensus. Exiting.");
                            decrementWTS();
                            break;
                        }
                        System.out.println(response);
                        String[] test = response.split("€");
                        String balanceToCheck = test[0].substring(test[0].length()-2);
                        try {
                            Integer.valueOf(test[0].substring(test[0].length()-2));
                        } catch(NumberFormatException nfe) {
                            balanceToCheck = test[0].substring(test[0].length()-1);
                        }
                        sendSockets("Proceed");
                        signature = signatureSetup(clientPrivateKey, "Proceed", signature, dsaForSign);
                        sendSockets(Base64.getEncoder().encodeToString(signature));
                        boolean otherAccount = false;
                        if (!Base64.getEncoder().encodeToString(clientAliasPB.getEncoded()).equals(Base64.getEncoder().encodeToString(publicKey.getEncoded()))) {
                            otherAccount = true;
                        }
                        response = readAndCheckBalanceSockets(balanceToCheck, otherAccount);
                        if (response.equals("Problem verifying received transactions. Possible byzantine server. Exiting.")) {
                            System.out.println("Problem verifying received transactions. Possible byzantine server. Exiting.");
                            decrementWTS();
                            break;
                        }
                        break;

                    //transfer_amount
                    case 2:

                        if (registered == false) {
                            System.out.println("Please register yourself first");
                            break;
                        }

                        incrementWTS();
                    
                        System.out.println("Insert account destination identifier:");
                        if (!input.hasNext()) {
                            System.out.println("Not a valid account identifier");
                            decrementWTS();
                            input.nextLine();
                            break;
                        }

                        try {
                            chosenAlias = input.nextLine();
                            destPk = getPublicKey(chosenAlias);
                            byte_pub = destPk.getEncoded();
                        } catch (NullPointerException npe) {
                            System.out.println("Not a valid alias");
                            sendSockets("error");
                            break;
                        }

                        sendSockets(operation + ";" + Base64.getEncoder().encodeToString(byte_pub) + ";" + accountAliasToWTS + ";" + Base64.getEncoder().encodeToString(byte_pub1));

                        hashes = votelessReadFromSockets();
                        hashesToSend = new String[4];
                        digest = MessageDigest.getInstance("SHA-256");
                        iter = 0;
                        while (true) {
                            if (iter == 4) {
                                    break;
                                }
                            correctHash = generateRandomString();
                            digest.update(correctHash.getBytes("UTF-8"));
                            if (Base64.getEncoder().encodeToString(digest.digest()).equals(hashes[iter])) {
                                hashesToSend[iter] = correctHash;
                                iter++;
                            }
                        }
                        sendHashSockets(hashesToSend, signature);

                        response = readAndVerifySockets();
                        if (response.equals("Couldn't reach a consensus. Exiting.")) {
                            System.out.println("Couldn't reach a consensus. Exiting.");
                            decrementWTS();
                            break;
                        }
                        
                        System.out.println("Insert account balance to transfer:");
                        if (!input.hasNextInt()) {
                            System.out.println("Not a valid amount");
                            decrementWTS();
                            input.nextLine();
                            sendSockets(-1);
                            break;
                        }

                        balance = input.nextInt();
                        if (balance < 0) {
                            System.out.println("Not a valid amount");
                            decrementWTS();
                            sendSockets(-1);
                            break;
                        }
                        signature = "signature".getBytes();
                        timestamp = System.currentTimeMillis();
                        toSign = operation + ";" + clientAliasPB + ";" + destPk + ";" + balance + ";" + timestamp;
                        signature = signatureSetup(clientPrivateKey, toSign, signature, dsaForSign);
                        sendSockets(balance); 
                        sendSockets(timestamp.toString());
                        sendSockets(Base64.getEncoder().encodeToString(signature)); 

                        response = readAndVerifySockets();
                        if (response.equals("Couldn't reach a consensus. Exiting.")) {
                            System.out.println("Couldn't reach a consensus. Exiting.");
                            break;
                        }
                        System.out.println(response);

                        break;

                    //receive_amount
                    case 3:

                        if (registered == false) {
                            System.out.println("Please register yourself first");
                            break;
                        }

                        incrementWTS();

                        System.out.println("Insert index of transaction to accept:");

                        if (!input.hasNextInt()) {
                            System.out.println("Not a valid index");
                            input.nextLine();
                            sendSockets(-1);
                            decrementWTS();
                            break;
                        }

                        index = input.nextInt();
                        sendSockets(operation + ";" + Base64.getEncoder().encodeToString(byte_pub1));
                        signature = "signature".getBytes();
                        timestamp = System.currentTimeMillis();
                        toSign = operation + ";" + clientAliasPB + ";" + index + ";" + timestamp;
                        signature = signatureSetup(clientPrivateKey, toSign, signature, dsaForSign);
                        sendSockets(index);
                        sendSockets(timestamp.toString());
                        sendSockets(Base64.getEncoder().encodeToString(signature));

                        hashes = votelessReadFromSockets();
                        hashesToSend = new String[4];
                        digest = MessageDigest.getInstance("SHA-256");
                        iter = 0;
                        while (true) {
                            if (iter == 4) {
                                    break;
                                }
                            correctHash = generateRandomString();
                            digest.update(correctHash.getBytes("UTF-8"));
                            if (Base64.getEncoder().encodeToString(digest.digest()).equals(hashes[iter])) {
                                hashesToSend[iter] = correctHash;
                                iter++;
                            }
                        }
                        sendHashSockets(hashesToSend, signature);

                        response = readAndVerifySockets();
                        if (response.equals("Couldn't reach a consensus. Exiting.")) {
                            System.out.println("Couldn't reach a consensus. Exiting.");
                            decrementWTS();
                            break;
                        }
                        System.out.println(response);
                        break;
                    
                    //audit
                    case 4:

                        if (registered == false) {
                            System.out.println("Please register yourself first");
                            break;
                        }

                        incrementWTS();

                        System.out.println("Insert account to audit:");

                        if (!input.hasNext()) {
                            System.out.println("Not a valid alias");
                            input.nextLine();
                            decrementWTS();
                            break;
                        }

                        try {
                            alias = input.nextLine();
                            publicKey = getPublicKey(alias);
                            byte_pub = publicKey.getEncoded();
                        } catch (Exception e) {
                            System.out.println("There is no such alias");
                            decrementWTS();
                            break;
                        }

                        signature = "signature".getBytes();
                        toSign = operation + ";" + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + ";" + System.currentTimeMillis() + ";" + Base64.getEncoder().encodeToString(byte_pub1);
                        signature = signatureSetup(clientPrivateKey, toSign, signature, dsaForSign);
                        sendSockets(toSign);
                        sendSockets(Base64.getEncoder().encodeToString(signature));

                        hashes = votelessReadFromSockets();
                        hashesToSend = new String[4];
                        digest = MessageDigest.getInstance("SHA-256");
                        iter = 0;
                        while (true) {
                            if (iter == 4) {
                                    break;
                                }
                            correctHash = generateRandomString();
                            digest.update(correctHash.getBytes("UTF-8"));
                            if (Base64.getEncoder().encodeToString(digest.digest()).equals(hashes[iter])) {
                                hashesToSend[iter] = correctHash;
                                iter++;
                            }
                        }
                        sendHashSockets(hashesToSend, signature);

                        response = readAndVerifySockets();
                        if (response.equals("Couldn't reach a consensus. Exiting.")) {
                            System.out.println(response);
                            decrementWTS();
                            break;
                        } else if (response.equals("No source account registered with that identifier")) {
                            System.out.println(response);
                            decrementWTS();
                            break;
                        }
                        System.out.println(response);
                        sendSockets("Proceed");
                        signature = signatureSetup(clientPrivateKey, "Proceed", signature, dsaForSign);
                        sendSockets(Base64.getEncoder().encodeToString(signature));
                        response = readAndCheckByzantineSockets();
                        if (response.equals("Problem verifying received transactions. Possible byzantine server. Exiting.")) {
                            System.out.println("Problem verifying received transactions. Possible byzantine server. Exiting.");
                            decrementWTS();
                            break;
                        }
                        break;
                    case 5:
                        String debug = "";
                        sendSockets(debug + operation); //ONLY here for debug purposes
                        break;

                    default:
                        break;
                }
            }
            catch(Exception e)
            {
                e.printStackTrace();
            }
        }

        try
        {
            input.close();
            out.close();
            in.close();
            socket.close();
        }
        catch(IOException i)
        {
            System.out.println(i);
        }
    }

    public void printTable() {
        String leftAlignFormat = "| %-9s | %-6d | %n";
        System.out.format("+-----------+--------+%n");
        System.out.format("| Operation | Number | %n");
        System.out.format("+-----------+--------+%n");
        System.out.format(leftAlignFormat, "Open Acc", 0);
        System.out.format(leftAlignFormat, "Check Acc", 1);
        System.out.format(leftAlignFormat, "Transfer", 2);
        System.out.format(leftAlignFormat, "Receive", 3);
        System.out.format(leftAlignFormat, "Audit", 4);
        System.out.format("+-----------+--------+%n");
    }

    public byte[] convertIntToByteArray(int value) {
        return new byte[] {
                (byte)(value >> 24),
                (byte)(value >> 16),
                (byte)(value >> 8),
                (byte)value };
    }

    public void checkForReplay(boolean verifies, String timestampString) {
        if (verifies) {
            for (String value: sigList) {
                if (value.equals(timestampString)) {
                    System.out.println("Problem with signature - Server-Client1");
                    return;
                }
            }
        } else {
            System.out.println("Problem with signature - Server-Client2");
            return;
        }
        sigList.add(timestampString);
        // debug print
        //System.out.println("Signature Verified");
    }

    public byte[] signatureSetup(KeyStore.PrivateKeyEntry pk, String toSign, byte[] signature, Signature dsaForSign) {
        try {
            dsaForSign.initSign(pk.getPrivateKey());
            dsaForSign.update(toSign.getBytes()); 
            signature = dsaForSign.sign(); 
        } catch (Exception e) {
            System.out.println(e);
        }
        return signature;
    }

    public boolean signatureVerify(PublicKey pb, String toSign, byte[] signature, Signature dsaForSign) {
        boolean verifies = false;
        try {
            dsaForVerify.initVerify(pb);
            dsaForVerify.update(toSign.getBytes()); 
            verifies = dsaForVerify.verify(signature); 
        } catch (Exception e) {
            System.out.println(e);
        }
        return verifies;
    }

    public PublicKey getPublicKey(String alias) {
        PublicKey getPk = null;
        Certificate cert = null;
        try {
            cert = ks.getCertificate(alias);
            getPk = cert.getPublicKey();
            
        } catch(Exception e) {
        }
        return getPk;
    }

    public PublicKey toPublicKey(String encodedB64) {
        PublicKey pb = null;
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            pb = factory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(encodedB64)));
        } catch(Exception e) {
            System.out.println(e);
        }
        return pb;
    }

    public void incrementWTS() {
        this.accountAliasToWTS += 1;
    }

    public void decrementWTS() {
        this.accountAliasToWTS -= 1;
    }

    public void sendSockets(String UTF) {
        try {
            for(DataOutputStream out: serverOutputs) {
                out.writeUTF(UTF);
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    public void sendSockets(Integer integ) {
        try {
            for(DataOutputStream out: serverOutputs) {
                out.writeInt(integ);
            }            
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    public void sendHashSockets(String[] hash, byte[] signature) {
        Integer iter = 0;
        try {
            for(DataOutputStream out: serverOutputs) {
                out.writeUTF(hash[iter]);
                signature = signatureSetup(clientPrivateKey, hash[iter], signature, dsaForSign);
                out.writeUTF(Base64.getEncoder().encodeToString(signature));
                iter++;
            }            
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    public String[] votelessReadFromSockets() {
        String read, sigRead;
        String[] splitRead;
        String[] retHashes = new String[4];
        boolean sigVerified = false;
        Integer iter = 0;
        for (DataInputStream ins: serverInputs) {
            try {
                read = ins.readUTF();
                splitRead = read.split(";");
                sigRead = ins.readUTF();
                sigVerified = signatureVerify(toPublicKey(splitRead[1]), read, Base64.getDecoder().decode(sigRead), dsaForVerify);
                if (sigVerified == false) {
                    System.out.println("Signature problem.");
                    continue;
                }
                checkForReplay(sigVerified, read);
                retHashes[iter] = splitRead[0];
                iter++;
            } catch (Exception e) {
                continue;
            }
        }
        return retHashes;
    }

    public String readFromSockets() {
        Map<String, Integer> votes = new HashMap<String, Integer>();
        String read;
        String[] splitRead;
        for (DataInputStream ins: serverInputs) {
            try {
                read = ins.readUTF(); 
                if (read.contains(";")) {
                    splitRead = read.split(";");
                    votes.put(splitRead[0], votes.getOrDefault(splitRead[0], 0) + 1);
                    continue;
                }
                votes.put(read, votes.getOrDefault(read, 0) + 1);
            } catch (Exception e) {
                continue;
            }
        }
        for (Map.Entry<String, Integer> entry: votes.entrySet()) {
            if (entry.getValue() > (4 * allowedFaults + 1)/2) {
                return entry.getKey();
            }
        }
        return "Couldn't reach a consensus. Exiting.";
    }

    public String readAndVerifySockets() {
        Map<String, Integer> votes = new HashMap<String, Integer>();
        String read, sigRead;
        String[] splitRead;
        boolean sigVerified = false;
        for (DataInputStream ins: serverInputs) {
            try {
                read = ins.readUTF();
                splitRead = read.split(";");
                sigRead = ins.readUTF();
                sigVerified = signatureVerify(toPublicKey(splitRead[1]), read, Base64.getDecoder().decode(sigRead), dsaForVerify);
                if (sigVerified == false) {
                    System.out.println("Signature problem.");
                    continue;
                }
                checkForReplay(sigVerified, read);
                votes.put(splitRead[0], votes.getOrDefault(splitRead[0], 0) + 1);
            } catch (Exception e) {
                continue;
            }
        }
        for (Map.Entry<String, Integer> entry: votes.entrySet()) {
            if (entry.getValue() > (4 * allowedFaults + 1)/2) {
                return entry.getKey();
            }
        }
        return "Couldn't reach a consensus. Exiting.";
    }

    public String readAndCheckByzantineSockets() {
        Map<String, Integer> votes = new HashMap<String, Integer>();
        String read, sigRead;
        String[] splitRead;
        boolean sigVerified = false;
        for (DataInputStream ins: serverInputs) {
            try {
                read = ins.readUTF();
                sigRead = ins.readUTF();
                splitRead = read.split("\\?");
                sigVerified = signatureVerify(toPublicKey(splitRead[0]), read, Base64.getDecoder().decode(sigRead), dsaForVerify);
                if (sigVerified == false) {
                    System.out.println("Signature problem.");
                    continue;
                }
                votes.put(read.substring(splitRead[0].length()), votes.getOrDefault(read.substring(splitRead[0].length()), 0) + 1);
            } catch (Exception e) {
                continue;
            }
        }
        for (Map.Entry<String, Integer> entry: votes.entrySet()) {
            if (entry.getValue() > (4 * allowedFaults + 1)/2) {
                return entry.getKey();
            }
        }
        return "Problem verifying received transactions. Possible byzantine server. Exiting.";
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

    public String readAndCheckBalanceSockets(String finalBalance, boolean otherAccount) {
        Map<String, Integer> votes = new HashMap<String, Integer>();
        String read, sigRead;
        String[] splitRead, balanceSplit, totalSplit;
        List<String> noPbList = new ArrayList<String>();
        boolean sigVerified = false;
        Integer initBalance = 10;
        for (DataInputStream ins: serverInputs) {
            try {
                read = ins.readUTF();
                sigRead = ins.readUTF();
                splitRead = read.split("\\?");
                sigVerified = signatureVerify(toPublicKey(splitRead[0]), read, Base64.getDecoder().decode(sigRead), dsaForVerify);
                if (sigVerified == false) {
                    System.out.println("Signature problem.");
                    continue;
                }
                totalSplit = read.substring(splitRead[0].length()+1).split("\\?");
                for (String soleTransaction: totalSplit) {
                    balanceSplit = soleTransaction.split(";");
                    try {
                        if (balanceSplit[5].equals("INCOMING") && otherAccount == false) {
                            initBalance += Integer.valueOf(balanceSplit[4]);
                        } else if (balanceSplit[5].equals("OUTGOING") && otherAccount == false) {
                            initBalance -= Integer.valueOf(balanceSplit[4]);
                        } else if (balanceSplit[5].equals("INCOMING") && otherAccount == true) {
                            initBalance -= Integer.valueOf(balanceSplit[4]);
                        } else if (balanceSplit[5].equals("OUTGOING") && otherAccount == true) {
                            initBalance += Integer.valueOf(balanceSplit[4]);
                        }
                    } catch (IndexOutOfBoundsException ioobe) {
                        continue;
                    }
                    
                }
                if (initBalance != Integer.valueOf(finalBalance)) {
                    continue;
                } else {
                    // debug print
                    //System.out.println("Successfully checked balance");
                    initBalance = 10;
                }

                votes.put(read.substring(splitRead[0].length()), votes.getOrDefault(read.substring(splitRead[0].length()), 0) + 1);
            } catch (Exception e) {
                e.printStackTrace();
                continue;
            }
        }
        for (Map.Entry<String, Integer> entry: votes.entrySet()) {
            if (entry.getValue() > (4 * allowedFaults + 1)/2) {
                return entry.getKey();
            }
        }
        return "Problem verifying received transactions. Possible byzantine server. Exiting.";
    }

    public static void main(String args[])
    {
        Client client = new Client();
    }
}
