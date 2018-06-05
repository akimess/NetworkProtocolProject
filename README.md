# NetworkProtocolProject
Chat Application

### Requirements: <br/>
**Python 2.7** <br/>
**PGPY library** <br/>

P.S. Tested on MacOS

### Arguments
-p --port **Your application port** <br/>
-n --neighbors **Your neigbors.** *format - ip:port:email* <br/>
-e --email **Your email** <br/>
-k --known **List of all known email that could be in the network** *format - ip:port:email* <br/>
-en --encryption **Enable encryption** *default - True* <br/>

### How to run
You need to specify the port, email, known email in the network.
When firing the second node, you will also need to state the active neighbor to whom you want to connect.

#### Example on how to run
*1st terminal:* **python main.py** <br/>
This will create a node using default parameters: <br/>
port 9999, email akim.essen@ttu.ee, known list of email ['127.0.0.1:9999:akim.essen@ttu.ee', '127.0.0.1:9998:essen@ttu.ee', '127.0.0.1:9997:test@ttu.ee']

*2nd terminal:* **python main.py -p 9998 -e essen@ttu.ee -n 127.0.0.1:9999:akim.essen@ttu.ee** <br/>
This will create a second node, with default known emails and connect to neighbor akim.essen@ttu.ee <br/>

*3rd terminal:* **python main.py -p 9997 -e test@ttu.ee -n 127.0.0.1:9998:essen@ttu.ee** <br/>
This will create a second node, with default known emails and connect to neighbor essen@ttu.ee <br/>

### GUI
I used Tkinter for the GUI. It is very basic. <br/>
First field is the message you want to send. <br/>
Second field is to whom you want to send (email). <br/>
"Send" button will send the message. <br/>
"Send file" button will open up a browse window, and once you select the file, it will automatically will send it. So remember to enter the email in the second field before that. <br/>

#### Hidden commands
First field: <br/>
*{list_nodes}* - Enter this, click send and it will list all of the active nodes in the network. <br/>

Second field: <br/>
*{to_all}* - Enter this, write any message in the first field, click send and it will send the message to all nodes in the network. <br/>


#### Disconnecting
Just close the window and it will send out the disconnect message to all nodes, and auto close the window after that.
