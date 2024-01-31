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
import java.util.concurrent.*;


public class Server {

    private Integer operation = -1, parameter = -1;
    private String response, signedString, encodedData, transactions, checkpoint, hashCheck = null;
    private boolean isValidAccount, sigVerified, replay = false;
    private PublicKey pb, backupPb = null;
    private byte[] signature = "signature".getBytes();
    private Signature dsaForSign, dsaForVerify = null;
    private List<String> sigList = new ArrayList<String>();

    public Server() {
        try {
            dsaForVerify = Signature.getInstance("SHA256withRSA");
            dsaForSign = Signature.getInstance("SHA256withRSA");
        } catch (Exception e) {
            System.out.println("Error while generating signature instances.");
        }
    }

    public void registerAccount(int operation, String[] splitString, String response, DataOutputStream out, DataInputStream in,
    Operations operationMethods, KeyStore.PrivateKeyEntry serverPvk, PublicKey serverPbk, FileOutputStream file,
    FileOutputStream backupFileOutput, ObjectOutputStream oos, ObjectOutputStream oos2) {
        try {
            encodedData = in.readUTF();
            sigVerified = signatureVerify(toPublicKey(splitString[1]), response, Base64.getDecoder().decode(encodedData), dsaForVerify); 
            if (!checkForReplay(sigVerified, response)) {
                response = operationMethods.openAccount(toPublicKey(splitString[1])) + ";" + Base64.getEncoder().encodeToString(serverPbk.getEncoded()) + ";" + System.currentTimeMillis();
                signature = signatureSetup(serverPvk, response, signature, dsaForSign);
                persistState(file, backupFileOutput, oos, oos2, operationMethods);
                operationMethods.setWTimestamp(toPublicKey(splitString[1]), 0);
                operationMethods.setRTimestamp(toPublicKey(splitString[1]), 0);
                out.writeUTF(response);
                out.writeUTF(Base64.getEncoder().encodeToString(signature));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void viewAccount(int operation, String[] splitString, String response, DataOutputStream out, DataInputStream in,
    Operations operationMethods, KeyStore.PrivateKeyEntry serverPvk, PublicKey serverPbk, String hashString, byte[] hash) {
        try {
            encodedData = in.readUTF();
            sigVerified = signatureVerify(toPublicKey(splitString[1]), response, Base64.getDecoder().decode(encodedData), dsaForVerify);           
            if (!checkForReplay(sigVerified, response)) {
                isValidAccount = operationMethods.isValidAccount(toPublicKey(splitString[3]));
                if (isValidAccount == false) {
                    response = "No account registered with that identifier;" + Base64.getEncoder().encodeToString(serverPbk.getEncoded()) + ";" + System.currentTimeMillis();
                    signature = signatureSetup(serverPvk, response, signature, dsaForSign);
                    out.writeUTF(response);
                    out.writeUTF(Base64.getEncoder().encodeToString(signature));
                    return;
                }
                encodedData = Base64.getEncoder().encodeToString(hash) + ";" + Base64.getEncoder().encodeToString(serverPbk.getEncoded()) + ";" + System.currentTimeMillis();
                out.writeUTF(encodedData);
                signature = signatureSetup(serverPvk, encodedData, signature, dsaForSign);
                out.writeUTF(Base64.getEncoder().encodeToString(signature));
                hashCheck = in.readUTF();
                if (hashCheck.equals(hashString)) {
                    System.out.println("Client successfully returned correct hash");
                } else {
                    return;
                }
                sigVerified = signatureVerify(toPublicKey(splitString[1]), hashCheck, Base64.getDecoder().decode(in.readUTF()), dsaForVerify);

                response = operationMethods.checkAccount(toPublicKey(splitString[3])) + ";" + Base64.getEncoder().encodeToString(serverPbk.getEncoded()) + ";" + System.currentTimeMillis();
                signature = signatureSetup(serverPvk, response, signature, dsaForSign);
                out.writeUTF(response);
                out.writeUTF(Base64.getEncoder().encodeToString(signature));
                transactions  = Base64.getEncoder().encodeToString(serverPbk.getEncoded()) + "?" + operationMethods.getClientSignatures(toPublicKey(splitString[1]));
                checkpoint = in.readUTF();
                encodedData = in.readUTF();
                sigVerified = signatureVerify(toPublicKey(splitString[1]), checkpoint, Base64.getDecoder().decode(encodedData), dsaForVerify);
                out.writeUTF(transactions);
                signature = signatureSetup(serverPvk, transactions, signature, dsaForSign);
                out.writeUTF(Base64.getEncoder().encodeToString(signature));
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    public void transferBalanceAccount(int operation, String[] splitString, String response, DataOutputStream out, DataInputStream in,
    Operations operationMethods, KeyStore.PrivateKeyEntry serverPvk, PublicKey serverPbk, FileOutputStream file,
    FileOutputStream backupFileOutput, ObjectOutputStream oos, ObjectOutputStream oos2, String hashString, byte[] hash) {
        try {
            encodedData = splitString[1];
            Integer clientWTimestamp = Integer.valueOf(splitString[2]);
            backupPb = toPublicKey(encodedData);
            isValidAccount = operationMethods.isValidAccount(backupPb);
            if (isValidAccount == false) {
                response = "No destination account registered with that identifier;" + Base64.getEncoder().encodeToString(serverPbk.getEncoded()) + ";" + System.currentTimeMillis();
                signature = signatureSetup(serverPvk, response, signature, dsaForSign);
                out.writeUTF(response);
                out.writeUTF(Base64.getEncoder().encodeToString(signature));
                return;
            }
            encodedData = Base64.getEncoder().encodeToString(hash) + ";" + Base64.getEncoder().encodeToString(serverPbk.getEncoded()) + ";" + System.currentTimeMillis();
            out.writeUTF(encodedData);
            signature = signatureSetup(serverPvk, encodedData, signature, dsaForSign);
            out.writeUTF(Base64.getEncoder().encodeToString(signature));
            hashCheck = in.readUTF();
            if (hashCheck.equals(hashString)) {
                System.out.println("Client successfully returned correct hash");
            } else {
                return;
            }
            sigVerified = signatureVerify(toPublicKey(splitString[1]), hashCheck, Base64.getDecoder().decode(in.readUTF()), dsaForVerify);

            response = "Account destination selected" + ";" + Base64.getEncoder().encodeToString(serverPbk.getEncoded()) + ";" + System.currentTimeMillis();
            out.writeUTF(response);
            signature = signatureSetup(serverPvk, response, signature, dsaForSign);
            out.writeUTF(Base64.getEncoder().encodeToString(signature));
            parameter = in.readInt();
            if (parameter == -1) {
                return;
             }
            try {
                dsaForVerify = Signature.getInstance("SHA256withRSA");
            } catch (Exception e) {
                System.out.println("exception");
            }
            signedString = operation + ";" + toPublicKey(splitString[3]) + ";" + backupPb + ";" + parameter + ";" + in.readUTF();
            String clientSignature = in.readUTF();
            sigVerified = signatureVerify(toPublicKey(splitString[3]), signedString, Base64.getDecoder().decode(clientSignature), dsaForVerify);
            replay = checkForReplay(sigVerified, signedString);
            if (!replay) {
                if (clientWTimestamp > operationMethods.getWTimestamp(toPublicKey(splitString[3]))) {
                    operationMethods.setWTimestamp(toPublicKey(splitString[3]), clientWTimestamp);
                    sigList.add(signedString);
                    //operationMethods.addReadTransactions(toPublicKey(splitString[3]), signedString + "?OUTGOING", false, 0);
                    response = operationMethods.transferBalance(toPublicKey(splitString[3]), backupPb, parameter, Base64.getDecoder().decode(clientSignature)) + ";" + Base64.getEncoder().encodeToString(serverPbk.getEncoded()) + ";" + System.currentTimeMillis();
                    signature = signatureSetup(serverPvk, response, signature, dsaForSign);
                    persistState(file, backupFileOutput, oos, oos2, operationMethods);
                    out.writeUTF(response);
                    out.writeUTF(Base64.getEncoder().encodeToString(signature));
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void receiveBalanceAccount(int operation, String[] splitString, String response, DataOutputStream out, DataInputStream in,
    Operations operationMethods, KeyStore.PrivateKeyEntry serverPvk, PublicKey serverPbk, FileOutputStream file,
    FileOutputStream backupFileOutput, ObjectOutputStream oos, ObjectOutputStream oos2, String hashString, byte[] hash) {
        try {
            encodedData = splitString[1];
            pb = toPublicKey(encodedData);
            parameter = in.readInt(); 
            if (parameter == -1) {
                return;
            }
            try {
                dsaForVerify = Signature.getInstance("SHA256withRSA");
            } catch (Exception e) {
                System.out.println(e);
            }
            signedString = operation + ";" + pb + ";" + parameter + ";" + in.readUTF();
            sigVerified = signatureVerify(pb, signedString, Base64.getDecoder().decode(in.readUTF()), dsaForVerify);
            encodedData = Base64.getEncoder().encodeToString(hash) + ";" + Base64.getEncoder().encodeToString(serverPbk.getEncoded()) + ";" + System.currentTimeMillis();
            out.writeUTF(encodedData);
            signature = signatureSetup(serverPvk, encodedData, signature, dsaForSign);
            out.writeUTF(Base64.getEncoder().encodeToString(signature));
            hashCheck = in.readUTF();
            if (hashCheck.equals(hashString)) {
                System.out.println("Client successfully returned correct hash");
            } else {
                return;
            }
            sigVerified = signatureVerify(toPublicKey(splitString[1]), hashCheck, Base64.getDecoder().decode(in.readUTF()), dsaForVerify);
            replay = checkForReplay(sigVerified, signedString);
            if (!replay) {
                System.out.println("Signature verified");
                sigList.add(signedString);
                //operationMethods.addReadTransactions(pb, signedString + "?INCOMING?", true, parameter);
                response = operationMethods.receiveBalance(pb, parameter, signedString) + ";" + Base64.getEncoder().encodeToString(serverPbk.getEncoded()) + ";" + System.currentTimeMillis();
                signature = signatureSetup(serverPvk, response, signature, dsaForSign);
                persistState(file, backupFileOutput, oos, oos2, operationMethods);
                out.writeUTF(response);
                out.writeUTF(Base64.getEncoder().encodeToString(signature));
            } else {
                System.out.println("Problem with signature");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void auditAccount(int operation, String[] splitString, String response, DataOutputStream out, DataInputStream in,
    Operations operationMethods, KeyStore.PrivateKeyEntry serverPvk, PublicKey serverPbk, String hashString, byte[] hash) {
        try {
            encodedData = in.readUTF();
            sigVerified = signatureVerify(toPublicKey(splitString[3]), response, Base64.getDecoder().decode(encodedData), dsaForVerify);           
            if (!checkForReplay(sigVerified, response)) {
                isValidAccount = operationMethods.isValidAccount(toPublicKey(splitString[1]));
                if (isValidAccount == false) {
                    response = "No source account registered with that identifier;" + Base64.getEncoder().encodeToString(serverPbk.getEncoded()) + ";" + System.currentTimeMillis();
                    signature = signatureSetup(serverPvk, response, signature, dsaForSign);
                    out.writeUTF(response);
                    out.writeUTF(Base64.getEncoder().encodeToString(signature));
                    return;
                }
                encodedData = Base64.getEncoder().encodeToString(hash) + ";" + Base64.getEncoder().encodeToString(serverPbk.getEncoded()) + ";" + System.currentTimeMillis();
                out.writeUTF(encodedData);
                signature = signatureSetup(serverPvk, encodedData, signature, dsaForSign);
                out.writeUTF(Base64.getEncoder().encodeToString(signature));
                hashCheck = in.readUTF();
                if (hashCheck.equals(hashString)) {
                    System.out.println("Client successfully returned correct hash");
                } else {
                    return;
                }
                sigVerified = signatureVerify(toPublicKey(splitString[1]), hashCheck, Base64.getDecoder().decode(in.readUTF()), dsaForVerify);
                response = operationMethods.auditAccount(toPublicKey(splitString[1])) + ";" + Base64.getEncoder().encodeToString(serverPbk.getEncoded()) + ";" + System.currentTimeMillis();
                signature = signatureSetup(serverPvk, response, signature, dsaForSign);
                out.writeUTF(response);
                out.writeUTF(Base64.getEncoder().encodeToString(signature));
                transactions = Base64.getEncoder().encodeToString(serverPbk.getEncoded()) + "?" + operationMethods.getClientSignatures(toPublicKey(splitString[1]));
                checkpoint = in.readUTF();
                encodedData = in.readUTF();
                sigVerified = signatureVerify(toPublicKey(splitString[3]), checkpoint, Base64.getDecoder().decode(encodedData), dsaForVerify);
                out.writeUTF(transactions);
                signature = signatureSetup(serverPvk, transactions, signature, dsaForSign);
                out.writeUTF(Base64.getEncoder().encodeToString(signature));
            };
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    // Auxiliary functions for code reusability

    public boolean checkForReplay(boolean verifies, String signedString) {
        if (verifies) {
            for (String value: sigList) {
                if (value.equals(signedString)) {
                    System.out.println("Problem with signature - Server-Client");
                    return true;
                }
            }
        } else {
            System.out.println("Problem with signature - Server-Client");
            return true;
        }
        sigList.add(signedString);
        System.out.println("Signature Verified");
        return false;
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

     public void persistState(FileOutputStream file, FileOutputStream backupFileOutput, ObjectOutputStream oos, ObjectOutputStream oos2, Operations operationMethods) {
        try {
            file = new FileOutputStream("log.txt");
            oos2 = new ObjectOutputStream(file);
            oos2.writeObject(operationMethods);
            file.close();
            oos2.close();
            backupFileOutput = new FileOutputStream("backupLog.txt");
            oos = new ObjectOutputStream(backupFileOutput);
            oos.writeObject(operationMethods);
            backupFileOutput.close();
            oos.close();
        } catch (Exception e) {
            System.out.println(e);
        }
    }

}