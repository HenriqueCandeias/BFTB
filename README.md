# BFTB - Byzantine Fault Tolerant Bank

"Highly Dependable Systems" MSc course group project. Grade: 15.25/20

## Setup

Install JDK and Maven. No external Java libraries were used.
Change to project directory where the /src folder is and compile using the following commands.

```
mvn package
```

## Run Server

Please make sure 4 servers are running before running the client.
Recommended ports are 5000, 5001, 5002 and 5003.

```
java -cp target/BFTB-1.0-SNAPSHOT.jar pt.tecnico.bftb.ServerAPI <port>
```

## Run Client

```
java -cp target/BFTB-1.0-SNAPSHOT.jar pt.tecnico.bftb.Client
```

## Demos

In this section we will demonstrate not only successful interactions between clients and the server but also edge cases where we test the system with respect to security and dependability properties.


### Full Simulation using every Operation

* Entities: 4 Servers, 2 Clients.

* First open 6 terminals (4 for the servers and 2 for the Clients) and run the commands on the setup and run sections; in order for the client to run correctly you will need to have setup the server first.

* Once running, insert "alias1" or "alias2" to get a public key. Then insert a password to get the corresponding private key; the password for the alias you choose is password + number of the alias (e.g. alias1 => password1).

* In the client terminal you will see a table that shows the operations you can perform.

* __Client 1:__

```
> 0
```

* Use this operation to register your account in the Servers. It is a mandatory procedure before using any other operations such as Transfer or Receive.

* __Client 2:__

```
> 0
```

* Do the same for __Client 2__.

* Now that you have opened both accounts you can start having them interact with eachother. 

* __Note: everytime there is a message from the Client to Server or vice versa, the integrity of said message is guaranteed throuh a signature__

* __Note: We also use a nonce in the form of the current Unix Timestamp in miliseconds and a hash to ensure further integrity of operations.__

* Let us view one of the opened accounts (type after the table of operations in the terminal):

* __Note: For every operation other than the register_account one, each server sends the client a hash which the client needs to solve before being able to further interact with the server. The solution validation is much easier to compute, and is done by the server. This is to prevent DoS attacks.__

```
> 1
```
* Use one of the alias used beforehand when opening the accounts for clients 1 & 2. Any account is able to use this operation for both themselves and any other registered account.

* Since the bank gives out 10€ when an account is opened we can now transfer over some money between the clients (type after the table of operations in the terminal):

```
> 2
```

* You will be asked to fill out the destination alias field (use already associated aliases).

* Then you can choose how much money you can send from source to destination.

* Now let us receive the money transfered as the destination alias (type after the table of operations in the terminal):

```
> 3
```

* You will be asked to fill out the alias field and the index which refers to the pending transaction when you perform a check_account operation.

* Finally, let us audit an account in the bank (type after the table of operations in the terminal):

```
> 4
```
* You will be asked to fill out the alias field of the account you would like to audit.

* Every operation received by the Client is subjected to a voting process. The client tries to discard possible byzantine servers and reach a consensus. One way to test this is:

* Make sure you have all 4 Servers open and at least one client. Insert in the client:

```
> 0
```

* The operation should work as normal. Now crash one of the servers with Ctrl-C and do the same operation in the client. Even though one server is down, there are still enough replicas alive to reach a consensus and give you an answer.

* Crash another servers and redo the operation. Since there are now two down servers and two available ones, it is no longer possible to reach a consensus with the server replies.
