package pt.tecnico.bftb;

import java.util.*;
import pt.tecnico.bftb.Account.transactionType;
import java.security.*;
import javax.crypto.*;
import pt.tecnico.bftb.Account.Triplet;
import java.io.*;
import java.util.concurrent.*;

public class Operations implements Serializable
{
    private List<Account> registeredAccounts;
    private ConcurrentHashMap<PublicKey, Integer> WTimestamps;
    private ConcurrentHashMap<PublicKey, Integer> RTimestamps;
    private static final long serialVersionUID = 1234567L;
    
    public Operations() {
        this.WTimestamps = new ConcurrentHashMap<PublicKey, Integer>();
        this.RTimestamps = new ConcurrentHashMap<PublicKey, Integer>();
        this.registeredAccounts = new CopyOnWriteArrayList<>();
    }

    public String openAccount(PublicKey accountIdentifier) {
        String socketMessage = "Successfully registered account with given identifier";
        for (Account account: registeredAccounts) {
            if (accountIdentifier.equals(account.getAccountIdentifier())) {
                socketMessage = "There is already an account registered with that identifier";
                return socketMessage;
            }
        }
        registeredAccounts.add(new Account(accountIdentifier));
        return socketMessage;
    }

    public String checkAccount(PublicKey accountIdentifier) {
        String socketMessage = "No account registered with that identifier";
        for (Account account: registeredAccounts) {
            if (accountIdentifier.equals(account.getAccountIdentifier())) {
                socketMessage = "Account balance is " + account.getAccountBalance() + "€\nPending transactions >\n";
                for (ConcurrentHashMap.Entry<PublicKey, ArrayList<Integer>> entry: account.getAccountPending().entrySet()) {
                    for (Integer balance: entry.getValue()) {
                        socketMessage += entry.getKey() + " " + balance + "€\n";
                    }
                }
            }
        }
        return socketMessage;
    }

    public String transferBalance(PublicKey sourceAccountIdentifier, PublicKey destinationAccountIdentifier, int balance, byte[] senderSignature) {
        String socketMessage = "Successfully sent transfer request";
        for (Account account: registeredAccounts) {
            if (sourceAccountIdentifier.equals(account.getAccountIdentifier())) {
                if (account.getAvailableBalance() < balance) {
                    socketMessage = "Not enough funds for transfer";
                    return socketMessage;
                }
                account.debitAvailableBalance(balance);
            }
        }
        for (Account account: registeredAccounts) {
            if (destinationAccountIdentifier.equals(account.getAccountIdentifier())) {
                account.addAccountPending(sourceAccountIdentifier, balance, senderSignature);
            }
        }
        return socketMessage;
    }

    //Method to verify if identifier is valid (for better feedback to client)
    public boolean isValidAccount(PublicKey accountIdentifier) {
        for (Account account: registeredAccounts) {
            if (accountIdentifier.equals(account.getAccountIdentifier())) {
                return true;
            }
        }
        return false;
    }

    public String receiveBalance(PublicKey accountIdentifier, Integer approvalIndex, String signedString) {
        String socketMessage = "Successfully approved incoming balance";
        Map.Entry<PublicKey, Integer> debitAccount = new AbstractMap.SimpleEntry<PublicKey,Integer>(null,-1);
        for (Account account: registeredAccounts) {
            if (accountIdentifier.equals(account.getAccountIdentifier())) {
                debitAccount = account.approveTransaction(approvalIndex);
                addReadTransactions(accountIdentifier,signedString + ";" + debitAccount.getValue() + ";INCOMING?", true, debitAccount.getValue());
                System.out.println("ESTOU A INSERIR ESTE VALOR" + debitAccount.getValue() + " NO " + accountIdentifier);
                if (debitAccount.getValue() == 0) {
                    socketMessage = "No pending transaction in such index";
                    return socketMessage;
                }
            }
        }
        for (Account account: registeredAccounts) {
            if (debitAccount.getKey().equals(account.getAccountIdentifier())) {
                account.debitBalance(debitAccount.getValue());
                addReadTransactions(debitAccount.getKey(),signedString + ";" + debitAccount.getValue() + ";OUTGOING;", true, debitAccount.getValue());
                System.out.println("ESTOU A INSERIR ESTE VALOR" + debitAccount.getValue() + " NO " + debitAccount.getKey());
                account.addOutgoingTransaction(debitAccount.getKey(), debitAccount.getValue());
            }
        }
        return socketMessage;
    }

    public String auditAccount(PublicKey accountIdentifier) {
        String socketMessage = "";
        for (Account account: registeredAccounts) {
            if (accountIdentifier.equals(account.getAccountIdentifier())) {
                socketMessage = "Transaction list >\n";
                for (Triplet<PublicKey, Integer, transactionType> entry: account.getOrderedTransactions()) {
                    socketMessage += entry.getFirst() + "-" + entry.getSecond() + "€ - " + entry.getThird() + "\n";
                }
            }
        }
        return socketMessage;
    }

    public void addReadTransactions(PublicKey accountIdentifier, String signature, boolean missingBalance, Integer parameter) {
        for (Account account: registeredAccounts) {
            if (accountIdentifier.equals(account.getAccountIdentifier())) {
                account.addClientSignatures(accountIdentifier, signature, missingBalance, parameter);
            }
        }
    }

    public String getClientSignatures(PublicKey accountIdentifier) {
        String socketMessage = "";
        for (Account account: registeredAccounts) {
            if (accountIdentifier.equals(account.getAccountIdentifier())) {
                socketMessage = account.getClientSignatures(accountIdentifier);
            }
        }
        return socketMessage;
    }

    public void setWTimestamp(PublicKey pb, Integer integ) {
        this.WTimestamps.put(pb,integ);
    }

    public void setRTimestamp(PublicKey pb, Integer integ) {
        this.WTimestamps.put(pb,integ);
    }

    public Integer getWTimestamp(PublicKey pb) {
        return this.WTimestamps.get(pb);
    }

    public Integer getRTimestamp(PublicKey pb) {
        return this.WTimestamps.get(pb);
    }
}