package pt.tecnico.bftb;

import java.util.*;
import java.util.AbstractMap.SimpleEntry;
import java.security.*;
import javax.crypto.*;
import java.io.*;
import java.util.AbstractMap;
import java.util.concurrent.*;

public class Account implements Serializable
{   
    private static final long serialVersionUID = 1234567L;
    public enum transactionType {
        OUTGOING,
        INCOMING
    }

    private int accountBalance;
    private int availableBalance;
    private PublicKey accountIdentifier;

    //Full ordered transaction history
    private ConcurrentHashMap<PublicKey, ArrayList<Map.Entry<transactionType, Integer>>> transactionHistory;

    //Incoming pendent
    private ConcurrentHashMap<PublicKey, ArrayList<Integer>> accountPending;

    //Full ordered transaction history
    private List<Triplet<PublicKey, Integer, transactionType>> orderedTransactions = new CopyOnWriteArrayList<>();

    //Byzantine Fault Tolerance
    private int currentTS = 0;
    private ConcurrentHashMap<PublicKey, ArrayList<String>> clientSignatures;


    public Account(PublicKey accountIdentifier) {
        this.clientSignatures = new ConcurrentHashMap<PublicKey, ArrayList<String>>();
        this.accountBalance = 10;
        this.availableBalance = this.accountBalance;
        this.accountIdentifier = accountIdentifier;
        this.transactionHistory = new ConcurrentHashMap<>();
        this.accountPending = new ConcurrentHashMap<PublicKey, ArrayList<Integer>>();
    }

    public void addClientSignatures(PublicKey accountIdentifier, String signature, boolean missingBalance, Integer parameter) {
        System.out.println(this.clientSignatures);
        System.out.println(this.clientSignatures.containsKey(accountIdentifier));
        if (this.clientSignatures.containsKey(accountIdentifier)) {
            if (missingBalance == false) {
                this.clientSignatures.get( accountIdentifier).add(signature);
            } else {
                System.out.println(getIndexBalance(parameter) + "AUUUUUUUUUUUUUUUUUUUUUUUUUUGH");
                this.clientSignatures.get(accountIdentifier).add(signature + getIndexBalance(parameter));
            }
            
        } else {
            if (missingBalance == false) {
                this.clientSignatures.put(accountIdentifier, new ArrayList<String>());
                this.clientSignatures.get(accountIdentifier).add(signature);
            } else {
                System.out.println("parameter" + parameter);
                System.out.println("signature" + signature);
                this.clientSignatures.put(accountIdentifier, new ArrayList<String>());
                System.out.println(getIndexBalance(parameter) + "AUUUUUUUUUUUUUUUUUUUUUUUUUUGH");
                this.clientSignatures.get(accountIdentifier).add(signature + getIndexBalance(parameter));
            }
            
        }
    }

    public String getClientSignatures(PublicKey accountIdentifier) {
        String socketMessage = "No client signatures";
        for (Map.Entry<PublicKey, ArrayList<String>> entry: clientSignatures.entrySet()) {
            socketMessage = entry.getValue() + "?";
        }
        return socketMessage;
    }

    public void addOutgoingTransaction(PublicKey accountIdentifier, int balance) {
        if (this.transactionHistory.containsKey(accountIdentifier)) {
            this.transactionHistory.get(accountIdentifier).add(new SimpleEntry(transactionType.OUTGOING, balance));
        } else {
            this.transactionHistory.put(accountIdentifier, new ArrayList<Map.Entry<transactionType, Integer>>());
            this.transactionHistory.get(accountIdentifier).add(new SimpleEntry(transactionType.OUTGOING, balance));
        }

        orderedTransactions.add(new Triplet(accountIdentifier, balance, transactionType.OUTGOING));
    }

    public void addAccountPending(PublicKey accountIdentifier, int balanceTransfer, byte[] senderSignature) {
        if (this.accountPending.containsKey(accountIdentifier)) {
            this.accountPending.get(accountIdentifier).add(balanceTransfer);
        } else {
            this.accountPending.put(accountIdentifier, new ArrayList<Integer>());
            this.accountPending.get(accountIdentifier).add(balanceTransfer);
        }

        this.currentTS++; 

        SignaturesOfTransaction sigsOfTransact = new SignaturesOfTransaction();
        sigsOfTransact.setSenderSignature(senderSignature);

    }

    public void addAccountBalance(int balance) {
        this.accountBalance += balance;
    }

    public void addAvailableBalance(int balance) {
        this.availableBalance += balance;
    }

    public void debitBalance(int balance) {
        this.accountBalance -= balance;
    }

    public void debitAvailableBalance(int balance) {
        this.availableBalance -= balance;
    }

    public Map.Entry<PublicKey, Integer> approveTransaction(int approvalIndex) {
        Map.Entry<PublicKey, Integer> pair = new AbstractMap.SimpleEntry<PublicKey, Integer>(null, 0);
        Integer iterations = 1;
        int currPkIters = 0;
        Integer balance = 0;
        for (Map.Entry<PublicKey, ArrayList<Integer>> mapEntry: this.accountPending.entrySet()) {
            for (Integer idx: mapEntry.getValue()) {
                if (iterations == approvalIndex) {
                    if (this.transactionHistory.containsKey(mapEntry.getKey())) {
                        this.transactionHistory.get(mapEntry.getKey()).add(new SimpleEntry(transactionType.INCOMING, this.accountPending.get(mapEntry.getKey()).get(currPkIters)));
                    } else {
                        this.transactionHistory.put(mapEntry.getKey(), new ArrayList<Map.Entry<transactionType, Integer>>());
                        this.transactionHistory.get(mapEntry.getKey()).add(new SimpleEntry(transactionType.INCOMING, this.accountPending.get(mapEntry.getKey()).get(currPkIters)));
                    }
                    balance = this.accountPending.get(mapEntry.getKey()).get(currPkIters);
                    orderedTransactions.add(new Triplet(mapEntry.getKey(), balance, transactionType.INCOMING));
                    this.addAccountBalance(balance);
                    this.addAvailableBalance(balance);
                    this.accountPending.get(mapEntry.getKey()).remove(currPkIters);
                    pair = new AbstractMap.SimpleEntry<PublicKey, Integer>(mapEntry.getKey(),balance);
                    return pair;
                }
                currPkIters++;
                iterations++;
            }   
            currPkIters = 0;
        }
        return pair;
    }

    public Integer getIndexBalance(int index) {
        Integer iterations = 1;
        int currPkIters = 0;
        Integer balance = 0;
        for (Map.Entry<PublicKey, ArrayList<Integer>> mapEntry: this.accountPending.entrySet()) {
            for (Integer idx: mapEntry.getValue()) {
                if (iterations == index) {
                    balance = this.accountPending.get(mapEntry.getKey()).get(currPkIters);
                    return balance;
                }
                currPkIters++;
                iterations++;
            }
            currPkIters = 0;
        }

        return balance;
    }

    public PublicKey getAccountIdentifier() {
        return this.accountIdentifier;
    }

    public int getAccountBalance() {
        return this.accountBalance;
    }

    public int getAvailableBalance() {
        return this.availableBalance;
    }

    public ConcurrentHashMap<PublicKey, ArrayList<Integer>> getAccountPending() {
        return this.accountPending;
    }

    public ConcurrentHashMap<PublicKey, ArrayList<Map.Entry<transactionType, Integer>>> getTransactionHistory() {
        return this.transactionHistory;
    }

    public List<Triplet<PublicKey, Integer, transactionType>> getOrderedTransactions() {
        return this.orderedTransactions;
    }

    public class Triplet<PublicKey, Integer, transactionType> implements Serializable {

        private static final long serialVersionUID = 1234567L;
        private PublicKey first;
        private Integer second;
        private transactionType third;

        public Triplet(PublicKey pk, Integer balance, transactionType type) {
            this.first = pk;
            this.second = balance;
            this.third = type;
        }

        public PublicKey getFirst() { return first; }
        public Integer getSecond() { return second; }
        public transactionType getThird() { return third; }
    }

    private class SignaturesOfTransaction implements Serializable {

        private static final long serialVersionUID = 1234567L;
        private byte[] senderSignature, receiverSignature;

        public void setSenderSignature(byte[] senderSignature) {
            this.senderSignature = senderSignature;
        }

        public void setReceiverSignature(byte[] receiverSignature) {
            this.receiverSignature = receiverSignature;
        }

        public byte[] getSenderSignature() {
            return this.senderSignature;
        }

        public byte[] getReceiverSignature() {
            return this.receiverSignature;
        }
    }
}