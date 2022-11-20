# Smartphone as a security token

The smartphone is an indispensable digital companion for many people in their daily lives and web security is an aspect every web application have to take in consideration when being developed. By these means, we decided to join these situations and develop a project, in regard of the course Network and Computer Security at Instituto Superior Técnico, on which the smartphone is used as a security token in order to grant more security when accessing a web application.

This project will be further explained throughout this README file, having the following sections:
- **Authors:** information about the developers of the project
- **General Information:** introduction to the project and an outline of the technologies used;
- **Getting Started:** prerequisites and installing instructions in order to be able to run the project on a local machine for development and testing purposes;
- **Demo:** tour of the best features and screenshots of the project running;
- **Deployment:** deployment of the project in a set of separate virtual machines, with network isolation;

## Authors

| Number | Name              | Email                               |
| -------|-------------------|------------------------------------|
| 93692  | Bernardo Quinteiro  | <bernardo.quinteiro@tecnico.ulisboa.pt> |
| 93700  | Diogo Lopes   | <diogo.andre.fulgencio.lopes@tecnico.ulisboa.pt> |
| 101360  | Jérémy Breton   | <jeremy.breton@tecnico.ulisboa.pt> |

## General Information

This project is composed by a web application that simulates a virtual wallet where you can deposit cash or transfer to other users and a smartphone application responsible for making sure the login on the web application is secure and trustable. For this, after logging in in the web application, the user will be prompted to insert an **authentication token** that is shown in the smartphone application. This security system can prevent badly intentioned users from logging in in your account since knowing the login credentials is not enough, the **authentication token** is always needed and is only accessible in the user personal smartphone.

### Built With

In regard to the **web application**, this is developed using [Python](https://www.python.org/) using the web framework [Flask](https://flask.palletsprojects.com/en/2.0.x/). This web framework has various extensions that were used during the development of the web application, such as [CSRF](https://flask-wtf.readthedocs.io/en/0.15.x/csrf/) to protect from Cross-Site Request Forgery attacks in which the attacker attempts to trick an authenticated user into performing a malicious action. Furthermore, we also used the extension [Talisman](https://github.com/GoogleCloudPlatform/flask-talisman) that handles setting HTTP headers that can help protect against a few common web application security issues and helps managing the HTTP or HTTPS connections. Apart from this, we also used the extension [SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/en/2.x/) that aims to simplify using SQLAlchemy with Flask and manages the connections to the MySQL server and [PyNaCl](https://pynacl.readthedocs.io/en/latest/) to offer key encryption and digital signatures.

For the database we decided to use [XAMPP](https://www.apachefriends.org/index.html) that is a software distribution which provides a [MySQL](https://www.mysql.com/) database server.

The smartphone application was developed in [Android Studio](https://developer.android.com/studio) using Android and [Java](https://www.java.com/pt-BR/). We also used some dependencies, such as [Advanced HTTP URL Connection](https://github.com/VishnuSivadasVS/Advanced-HttpURLConnection) to manage the connections between the application and the webserver and [LazySodium](https://github.com/terl/lazysodium-android) to offer key encryption and digital signatures in Android.

PyNaCl and LazySodium are libraries for Python and Java, respectivelly, from the library [LibSodium](https://libsodium.gitbook.io/doc/) which is a software library for encryption, decryption, signatures, password hashing, between others. 

## Getting Started

In this section will be explained how to setup and run the project in the local machine for development and testing purposes. In the **deployment** section will be explained how to deploy the project on a live system.

### Prerequisites

In order to setup the project in a local machine we will be using **Windows 10**. 

Firstly, there is the need to install **XAMPP**, that is a software distribution which will provide the MySQL server and install **Android Studio** to be able to simulate a smartphone and run the developed application.

There will also be necessary for the **deployment** section a [Parrot](https://www.parrotsec.org/virtual/) ova that will be used to create 2 virtual machines (user and server) and [Genymotion](https://www.genymotion.com/) to simulate a smartphone in a virtual environment.

### Installing

After completing the prerequisites we'll have to install [**Python**](https://www.python.org/downloads/) from their website (at least version 3.9) and then install **pip** which is a package installer for **python**, which can be done by following this simple tutorial [PipInstall](https://www.geeksforgeeks.org/how-to-install-pip-on-windows/).

Now there is the need to install all the **python** packages, what can be done with the following commands:
- **Flask:** ```pip install Flask```
- **Flask-SQLAlchemy (manage database):** ```pip install -U Flask-SQLAlchemy```
- **Flask-WTF (CSRF):** ```pip install -U Flask-WTF```
- **MySQL-connector:** ```python -m pip install mysql-connector-python```
- **PyNaCl (Networking and Cryptography library):** ```pip install pynacl```
- **Talisman (Web application security issues):** ```pip install talisman```
- **PyMySQL:** ```pip install pymysql```
- **PyTest:** ```pip install pytest```

By this moment, all the installations have been done and we can proceed to **running** the project phase.

#### XAMPP
Firstly, open **XAMPP** and start the **Apache** and **MySQL** modules, what will start the **MySQL server**. 

![](https://cdn.discordapp.com/attachments/829496008815280128/936455675100426301/unknown.png)

To access the **database GUI**, click on the **Admin** blue bordered button shown in the picture above, which will bring you to **phpMyAdmin**. Here we will create a **new database** with collation **utf8mb4_general_ci** and name it **mfadb**.

![](https://cdn.discordapp.com/attachments/829496008815280128/936459092170518568/unknown.png)

We should have **phpMyAdmin** containing the **mfadb** as shown in the picture above, finishing **XAMPP** configuration.

#### Python server
The **python** server is configured in the ```/Website``` directory. In the ```main.py``` file change the **host** to the machine **ipv4** and in order to start the server, open a **windows command prompt** in the mentioned directory and run the command ```python main.py```. This will create the **user** table (if it doesn't exist yet) in the above created database (mfadb) and the server will be listening on **ipv4 port 8080**. Type ```ipv4:8080``` in a web browser and a **Sign In** page should appear.

To finish configurating the **python server** we need to execute the **python** file ```random_loginToken.py``` that will generate a unique random length 10 authentication token for each user in the **mfadb database** every 30 seconds.

#### Android Studio
Finally, we have to setup the **smartphone application**. For this, start **Android Studio** and open the ```/AndroidApp``` directory in this program. Firstly, inside **Gradle Scripts**, modify the file ```local.properties``` in order to contain the path to your **Android SDK** and then in ```app/java/fr.ghizmo.mfapp``` it's possible to find the **main** classes of the **Android app**. In the ```MainActivity``` class change the variable ```ip``` to the machine **ipv4**. To initialize the app, click the ***play*** button on the topBar and a virtual smartphone should start with app running.

**The Windows environment should be looking similar to the one presented in the image below**

![](https://cdn.discordapp.com/attachments/829496008815280128/936473007776493578/unknown.png)

### Testing

The tests created for the **Android application** can be found in the directory ```AndroidApp/MFAPP/app/src/test``` and were created using JUnit which is an open-source framework that supports the creation of automated tests for the **Java** programming language. These can be run by clicking the **play** arrow next to the test or by running the following command inside the application folder ```AndroidApp/MFAPP```:

```gradlew test```


## Demo

If the windows environment is as shown as in the previous picture, we are ready to proceed to the *demonstration* phase, on which we'll go through every possibility that can occur while running the project and explaining what is happening in the background.

- **Register**

We are in the ```/``` route which is where the user can **login** and renders the **html** page for the **sign in**.
Since we still haven't created a user in the **mfadb database** we will have to click the **sign up** link on the bottom right of the **sign in** box to be redirected to the ```/register``` route. Here it's possible to register a new **user** by filling in the following parameters:

**Username:** at least 4 characters long (ex: demouser)
**Email:** has to be of type **email** (ex: demouser@x.x)
**Password:** at least (8 characters long, 1 uppercase, 1 lowercase, 1 number, 1 special character) (ex: Demouser2022!)

Now we can **create account** and the **user** should be inserted into the **user table** in **mfadb database**, looking like this:

![](https://cdn.discordapp.com/attachments/829496008815280128/936584453579501608/unknown.png)

Each user has the following columns in the database:

**id:** integer incremented every time a new user is added (**unique**)
**username:** chosen username for the user (**unique**)
**email:** chosen email for the user (**unique**)
**password:** user password hashed using secure hash algorithm **SHA1**
**money:** available cash for the user
**createToken:** 10 length token generated after user registration that will need to be inserted in the smartphone application in order to link the smartphone with the user account (**unique**)
**loginToken:** 10 length token generated every 30 seconds (ensures freshness) for each user that has already linked the smartphone app to their account with createToken (**unique**)
**smartphoneLinked:** is changed to **1** after the user links the smartphone app to his account with createToken
**pubkuser:** user public key used to encrypt messages and send them securely ensuring integrity (the message hasn't been opened or tampered with) and confidentiality (**unique**)

Now after understanding all the available **user variables** we can proceed with the demonstration.

- **Login**

After creating an account, the user should be redirected back to the **login** route (```/```) where is able to **sign in** using the credentials defined before.
If the credentials are incorrect, a red pop up will appear,

![](https://cdn.discordapp.com/attachments/829496008815280128/936589696291717171/unknown.png)

otherwise, a green pop will appear and the user should be redirected to the ```/authentication``` route

![](https://cdn.discordapp.com/attachments/829496008815280128/936590177147686993/unknown.png)

- **Authentication**

In this phase, in order for the user to proceed, an **authentication token** (loginToken) will need to be inserted. This token is only available through the smartphone application of the smartphone linked to the user account, which ensures authentication.

The message on the container varies wheter the smartphone is linked or not

| Not linked (createToken to be introduced in smartphone) | Linked |
| -|-|
| ![](https://cdn.discordapp.com/attachments/829496008815280128/936592987717242920/unknown.png) | ![](https://cdn.discordapp.com/attachments/829496008815280128/936608886042021899/unknown.png)  |

Since we are a new user, the smartphone is **not linked** so we have to go to the virtual smartphone and insert the login credentials of the account we created before. 

If the credentials are incorrect, a prompt will be shown, on the other hand, if the user successfully logs in, the **public keys** of the server and the smartphone application will be exchanged, this way they can communicate securely ensuring **authentication**. 

Another page will appear for the user to insert the **createToken** shown on the web application, as shown in the image below:

![](https://cdn.discordapp.com/attachments/829496008815280128/936595367758278736/unknown.png)

After clicking the **verify** button, in order for this message to travel securely to the server, some backend steps will be executed:

**Digital Signature:** in order for the server to believe that the message was created by the smartphone application such that they cannot deny sending it (authentication and non-repudiation) and that the message was not altered in transit (integrity), this message (**createToken**) is **signed** using ```LazySodium cryptoSignLazy```.

**Key Encryption:** the signed message will then be **encrypted** using the **server public key** exchanged before and a random **nonce** will be generated, this way we can assure confidentiality. This encryption will be done using ```LazySodium cryptoBoxLazy```

This way, the **server** will receive an encrypted(signed(message)), a nonce randomly generated by the app and the sign public key. These steps can ensure **confidentiality**, **integrity** and **non-repudiation**.

After reversing these steps, the server will compare the obtained **createToken** with the user one present in the **mfadb database** and if they match, **smartphoneLinked** will be set to **1** and the user row in the database should be looking like this:

![](https://cdn.discordapp.com/attachments/829496008815280128/936610289078648922/unknown.png)

(**createToken** and the **server public key** will be stored privately in the smartphone shared preferences, this way this verification will only have to be done **once manually** and the other times the user logs in the app these values will be used **automatically** ensuring this smartphone is the one linked to the user account)

After the **createToken** is verified by the server, the smartphone application will make a request to ```/loginToken``` sending the **email** and the encrypted(signed(createToken)) again in order to ensure a secure communication. 

The server will request the **loginToken** to the **mfadb** and will do the same process the smartphone application did before, signing the token using ```PyNaCl nacl.signing``` and encrypting using ```PyNaCl nacl.public```. 

The smartphone application will reverse this and show a new page with the **loginToken** as presented under:

(the show token will be different from the presented above in the **mfadb database** since it's generated a new **loginToken** every 30 second, which ensures **freshness**)
![](https://cdn.discordapp.com/attachments/829496008815280128/936623488075194368/unknown.png#center)

Now the user can insert this **loginToken** in the **Authentication Token** field in the web application and this will be compared to the one present in the **mfadb database**. If they don't match a prompt will be displayed, otherwise, the user will be redirected to the route ```/home_user``` that will look like:

![](https://cdn.discordapp.com/attachments/829496008815280128/936631837474848858/unknown.png)

- **Home User**

Reaching this phase, the user has successfully logged in and authenticated with the **loginToken** shown on the linked smartphone. Now it's possible to do some activities in the virtual wallet, such as:

**Deposit:** the user will be redirected to the route ```/deposit```, on which an html page will be rendered where it's possible to input the ammout of money wanted to deposit to the virtual wallet

**Send Money:** the user will be redirected to the route ```/send_money```, on which an html page will be rendered where it's possible to input the ammout of money wanted to send to another user of this virtual wallet by his **unique** username

**Logout:** the user will be redirected to the route ```/``` where there will be the need to login and input **loginToken** in order to authenticate back to the virtual wallet

## Deployment

In this subsection will be explained how to deploy the project into an internal network constituted by:

**Server virtual machine:** this machine will be running the **python** server, **XAMPP** with the **MySQL** server and the python file that randomly generates a unique 10 length **loginToken** for each user present in the database every 30 seconds.

**Samsung BLA BLAH:** will be created in **Genymotion** and will be a virtualized smartphone simulating the user smartphone on which will be able to run the developed application.

**User virtual machine:** this machine will be simulating the user computer, on which he'll access the **python server address** in order to login to the virtual wallet.

Firstly, we will create **2 Parrot virtual machines in virtual box** with the OVA downloaded before. 
When double-clicking the .ova file virtual box will open. Choose the location for the virtual machines and name one "User MFA" and the other "Server MFA". This should be the setup in virtual box:

![](https://cdn.discordapp.com/attachments/829496008815280128/936650297948925992/unknown.png)

Now we will have to set the Network settings for these virtual machines:

| | Both Virtual Machines |
| -------|-------------------|
| Adapter 1 | **Attached to:** Internal Network, **Name:** MFA, **Promiscious mode:** Allow VMs |
| Adpater 2 | **Attached to:** NAT | **Attached to:** NAT |

Now we will have to configure the connection between these virtual machines.

In the server virtual machine run the command: ```sudo ifconfig eth0 192.168.0.100/24 up```
In the user virtual machine run the command: ```sudo ifconfig eth0 192.168.0.10/24 up```

For testing purposes try to **ping Server MFA** from **User MFA** and the other way around. If this test succeeds, we can proceed to the next steps.
If you have some problems, do: ```sudo /etc/init.d/networking force-reload```
And try reload the vms.

Now we we will have to install **XAMPP** (for linux) on **Server MFA**, for this go to **XAMPP** website (https://www.apachefriends.org/download.html) and download the 7.4.27 version. Save this file and run the following commands on it's directory:

```chmod +x xampp-linux-x64-7.4.27-2-installer.run```
```sudo ./xampp-linux-x64-7.4.27-2-installer.run```

By running XAMPP, you can turn ON the MySQL Database and Apache

![](https://media.discordapp.net/attachments/914798068279427083/936617935647162378/unknown.png)

So, everything is implemented to turn on the python server, this can be done with the following commands:

```python3 main.py```
```python3 random_loginToken.py```

In order to prevent some DDoS attacks, these iptables commands will drop invalid packets and drop TCP packets that are new and not SYN:

```/sbin/iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP```

```/sbin/iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP```

Now you can access the web application hosted by the wallet server in the user virtual machine by inserting the following address in browser:

```192.168.0.100:8080```

In genymotion you need to install a smartphone (by clicking on + on top right of genymotion).

We weren't able to put internal network for smartphone in genymotion so we have to put bridge for the conenction and we can move to bridge connection for the VMs. And look at the IP of adaptaters used by each VMs.

In order to install the application you need to install Android Debug Bridge (adb)
(https://developer.android.com/studio/releases/platform-tools)
When it's done you have to turn on the smartphone, put the apk file of the application in the directory of adb. And then run the command ```./adb install MFAPP.apk```.
So it will install the app on the smartphone. Now you can click on it on your applications.

We weren't able to fully deploy the smartphone in a virtual environment for it to be able to communicate in an internal network with the other vms, so running the project for testing is the better way to get all parts to work perfectly.



















