# How to use SSS client server
## Starting the Client and Server
In one terminal:
```BASH
cd Server/
sudo python server.py
```
In another terminal:
```BASH
python Client.py
```
## Runnng Client Commands
### Register
```BASH
Function: reg
name: <New_User_Name>
password: <New_Password>
```
### Login
```BASH
Function: login
name: NewUser
password: 1234
```
### Logout
#### Set Username
If for some reason the client crashes. In order to Login you must logout first to renew the session. To logout you first need to set you username of the intended user.
```BASH
Function: SetName
name: NewUser
````
#### Logout
```BASH
Function: LogOut

OUTPUT: Session ClOSED
```


### Check In
If the file is a new file the DID will equal the filename if the file is a file you are updating the DID id the hash of the file which you can get from the search function or by the output of the initial checkin. Flag inpute can be "INTEGITY","CONFIDENTIAL","NONE".

```BASH
Function: CheckIn
DID: tmp.txt
Flag: CONFIDENTIAL
File path: tmp.txt

OUTPUT:
FID  af694dcfabcadd0ebf7407b4be970142972ef41b
````
```BASH
Function: CheckIn
DID: af694dcfabcadd0ebf7407b4be970142972ef41b
Flag: CONFIDENTIAL
File path: tmp.txt

OUTPUT:
FID  af694dcfabcadd0ebf7407b4be970142972ef41b
```
### Search
```BASH
Function: search
FileName:ALL

OUTPUT:
Filename: key.priv
Owner: 1
DID: 0cd5ca1dd8cc09ead740a3b860e9b81da365037c

Filename: new
Owner: test1
DID: 2eecc02dc033e0aa85cd7a116626136bf4067d85

Filename: af694dcfabcadd0ebf7407b4be970142972ef41b
Owner: NewUser
DID: af694dcfabcadd0ebf7407b4be970142972ef41b

Filename: INTEGRITY
Owner: 2
DID: ca5fe8621eab7de365e7415bf63a9aec2b7443be

Filename: test
Owner: 1
DID: ee89026a6c5603c51b4504d218ac60f6874b7750

````

### Check Out
```BASH
Function: CheckOut
DID: af694dcfabcadd0ebf7407b4be970142972ef41b
````
The file will save in the current directory with the name as the DID of the file checked out.
### Delegation
```BASH
Function: Delegation
DID: af694dcfabcadd0ebf7407b4be970142972ef41b
Target User: ALL
Time:600
Permit (e.g. "rm, in, out"): rm,in,out

OUTPUT:
DELEGATION SUCCESSFUL
````
### Delete
```BASH
Function: Delete
FileName: af694dcfabcadd0ebf7407b4be970142972ef41b
````



