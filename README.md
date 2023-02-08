# NetSecFinalProject

(*All 3 folders in this repository are Netbeans Project Folders*)

Jonathan Vasallo, Liam Twomey, Dylan Tivnan
Network Security
5/10/2021

Introducing our group’s project we all decided that creating a Password Safe over a client
and server communication would be a secure mechanism that provides the correct qualifications
that are needed. The functionality of our Password safe starts with a Login interface where the
client must make a decision. The current user, as we will be referring to the most recent client
connection, can initiate a connection with the server after inputting the correct IP and port
number. Without a correct input of those to components no connection can be made preventing
any action from occurring otherwise. Upon a successful connection to the database server where
all of the information will be stored and security backed, an action to login or create a new user
account must have been selected. Starting off with the “create user account” option the current
user will be able to create a completely new account with the username and password of their
choosing. Upon confirmation of the request a communication will be initiated to the server
containing 4 values. These values are concatenated together into one string marked as
“CREATE:Username:Password:IV”. The values include a String “CREATE” to indicate that the
current user has selected the username, password, and the corresponding Base.64.String IV.

These values stored together are sent to the server via a socket connection. Once the message is
sent, the server awaits a connection and then the message that comes after it. The server then
takes this message and separates it into the 4 components that are specific to the original current
user request by using the split operator upon each colen the message contains. Now that the
server has these 4 values it can start encrypting the data using HMAC encryption. The encrypted
values now can be stored into the password database that lives in the server constantly. Once the
values have been successfully added and stored correctly into the password database, a message
indicating the successful creation of a username will be seen by the current user on the client side
as the server sends a confirmation message. As for the other side of functionality on the login
screen for the client, there is an option to login to the password safe, in order for the user to login
they must have already created an account previously. The username and password the current
user enters will then be stored into a string similarly to when the current user created the account
that holds 4 values this time instead. The values incorporated that will be concatenated are a
string “AUTH” that indicates the current user wants to login, the username, the password, and
lastly the one-time-password. Once these values are linked together via colons in a string, they
will be sent to the server. Upon arrival, the server gets the indicator that the request sent by the
current user is trying to login by reading the first part of the string “AUTH”. The server now
knows that the current user has sent information and it is time to authenticate this information.
First the server looks-up the information provided to see if there is an exact match that currently
lives in the password database. If there exists an exact match in the password database then we
will extract the HMAC key and the IV that corresponds to the record we have found a match for
on the server's end. Once we have the HMAC key the server then will create a
one-time-password object that will reflect whether or not the one-time-password that the client
sent over is valid or not. If the verification holds true then the server will then assemble a string
that contains the IV to send back to the client. This particular string holds the values “OK: IV”,
and on not verifying the String will simply read “NOK”. Once the message has been sent the
client will receive the message and act accordingly to the first part of the string. “OK” means that
the client is notified that their login request has been successful and the interface will then
change to the password safe interface. On there other hand, an unsuccessful attempt will result in
a message pop-up mentioning that the current user will have to try again. The current user now
has access to the password safe, and can now either add new pieces of information to the
password safe database or search for certain information that currently exists on the password
safe database. Let's discuss first the creation of data, upon the password safe interface start-up
there will be 3 text boxes that require information of a website, username, and password to
associate all to a specific location. This information is then stored so it can be sent to the server
as a concatenated string that looks like “ADD:Username:Website:Password:Nonce”. However,
the username and password are first encrypted using AES GCM in the client before sending
anything to the server to further secure the information sent to prevent man in the middle attacks,
and also the nonce extends this property of security to prevent replay attacks from occurring at
any point. Upon delivery of this information sent by the client, the server then sees the beginning
of the string “ADD” to start adding the corresponding information to the password safe database.
The encrypted username and password along with the website name are then inputted into the
password safe database where they can be accessed later on when the current user tries to search
the information he/she inputted originally. The information is now stored and “OK” as a string is
sent from the server to the client and with this indicator the current user will experience a pop-up
that indicates their entry has been successfully added. The last piece of functionality that our
password safe interface on the client side has is to search up information they have already added
to the password database previously. In order to search the password safe they must first click the
option to “Lookup”. Now that this has been selected a pop-up will appear for the current user to
type in the website they would like to find their personal information on. On the backend of the
client before anything is sent to the server, the username is then encrypted using AES GCM, and
the website and nonce are also included in the concatenation of the string that will be sent.
“LOOKUP” will be the server's indicator to look up information in the password database,
however the actual string will look like “LOOKUP:username:website:nonce”.

Once these values are assembled the server will accept its message to look up the following
username and website that match correctly in the password safe database. Once there is a match
the server will send the “website:password” where the password is still encrypted and the
website is the same. The server then sends this string over to the client and upon arrival to the
client, the client will then extract its information. The password in this case is still encrypted so
the client then decrypts it to be stored as a string. This is now assembled in a pop-up menu
indicating the website the current user looked up, and the username and password that were
originally entered at the time of adding this entry to the password safe database. The current user
can create as many entries for various websites and search for all of them so long as they exist in
the server's password safe database. 
