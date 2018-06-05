import socket, argparse, md5, os, time, copy
from encryption import Encryption
from threading import Thread
from utils import bitstring_to_bytes, nb, bn
from Tkinter import *

#, default=["127.0.0.1:9999:akim.essen@ttu.ee"]
parser = argparse.ArgumentParser(description='Network Protocol built on UDP')
parser.add_argument('-p', '--port', default=9999, type=int,help='Port to listen (default 9999)')
parser.add_argument('-n', '--neighbors', default=[], nargs='+', help='Neighbors IP and Ports')
parser.add_argument('-e', '--email', default="akim.essen@ttu.ee", help="TTU email")
parser.add_argument('-k', '--known', default=['127.0.0.1:9999:akim.essen@ttu.ee', '127.0.0.1:9998:essen@ttu.ee', '127.0.0.1:9997:test@ttu.ee'], nargs='+', help='Known list of nodes')
parser.add_argument('-en', '--encryption', default=True, type=bool, help='Enable Encryption')

args = parser.parse_args()

'''
Global variables:
updateTable - do we need to update the optimized version of the routing table
version - packet version
sourceAddress - hash of our email
routingTable - full routing table, holds all routes as {'destination', 'nextHop', 'metric'}
minifiedTable - optimized table for routing
routingMessage - optimized table for sending to neighbor
knownTable - known emails, which could appear in the network. This is used, because we receive the hash of email and we need to real email
chunkingHistory - keep track of chunking
ackHistory - keep track of ACKs that we are waiting for
neighbors - our node neighbors
'''
updateTable = True
version = '\x01'
sourceAddress = md5.new(args.email).digest()
routingTable = []
minifiedTable = []
routingMessage = ''
knownTable={}
chunkingHistory = {}
ackHistory = {}
neighbors = args.neighbors

UDP_IP = '127.0.0.1'
UDP_PORT = args.port

'''
Init function.
1) Create an object for known emails in the network. So we could map hash email to plain email.
2) Send init tables to each neigbor stated
'''
def init():

    if not os.path.isfile("first.asc"):
        Encryption.generate_certificates()

    known = args.known
    for k in known:
        kIP, kPORT, kEmail = k.split(':')
        hashK = md5.new(kEmail).digest()
        knownTable[hashK] = {
            'email': kEmail,
            'IP': kIP,
            'PORT': int(kPORT)
        }

    routingTable.append({
            'destination': sourceAddress,
            'nextHop': sourceAddress,
            'metric': 0
    })

    for neighbor in neighbors:
        neighborIP, neighborPORT, neighborEMAIL = neighbor.split(':')
        neighborPORT = int(neighborPORT)
        neighborEMAIL = md5.new(neighborEMAIL).digest()
        sendRoutingTable(neighborIP, neighborPORT, neighborEMAIL)
    pass

'''
Create a packet for sending.
Here we also check what next packet number should be.
'''
def buildPacket(packetType, ttl, confID, destAdd, layer4Type, payload, dIP, dPORT):
    packetNumber = 0
    if destAdd in ackHistory:
        while packetNumber in ackHistory[dIP + ":" + str(dPORT)]:
            packetNumber += 1
    layer3 = version + nb(packetNumber, 2) + packetType + \
        ttl + confID + '\x00' + sourceAddress + destAdd
    packet = layer3 + layer4Type + payload
    return packet, packetNumber

'''
Send the ACK packet back to sender.
'''
def sendAck(packetNumber, destinationAddress, nIP, nPORT):
    global sock
    packet, _ = buildPacket('\x04', nb(15,1), packetNumber, '\x00', sourceAddress, destinationAddress, nIP, nPORT)
    sock.sendto(packet, (nIP, nPORT))
    pass

def buildChunkedPayload(streamId, chunkId, payload, status='\x00'):
    return status + nb(streamId, 3) + nb(chunkId, 8) + payload

'''
This function will broadcast the routing table to each neighbor.
Every 30 seconds.
'''
def broadcastRoutingTable():
    while True:
        for neighbor in neighbors:
            neighborIP, neighborPORT, neighborEMAIL = neighbor.split(':')
            neighborPORT = int(neighborPORT)
            neighborEMAIL = md5.new(neighborEMAIL).digest()
            sendRoutingTable(neighborIP, neighborPORT, neighborEMAIL)
        time.sleep(30)
    pass

'''
Function will send the packet to destination.
Init the ttl, so we could drop the packet after 15 retries.
'''
def sendPacket(packet, neighborIP, neighborPORT, packetNumber):
    dest = neighborIP + ":" + str(neighborPORT)
    if dest not in ackHistory:
        ackHistory[dest] = {}
    ackHistory[dest][packetNumber] = {
        'packet': packet,
        'ttl': 0
    }
    sock.sendto(packet, (neighborIP, neighborPORT))

'''
Send routing table to destination.
1) Retrieve minified routing table
2) Decide on packet type, depending on if it is encrypted
3) Depending on the size of the message, chunk it
'''
def sendRoutingTable(neighborIP, neighborPORT, neighborEMAIL):
    message = retrieveRoutingTable()
    pChunkedType = '\x0D' if args.encryption else '\x05' 
    pWholeType = '\x09' if args.encryption else '\x01'
    if args.encryption: 
        message = Encryption.encrypt(message)
    if len(message) > 59:
        left = len(message) % 47
        packageNumbers = (len(message) - left) / 47
        for x in xrange(packageNumbers):
            msg = message[x*47:(x+1)*47]
            streamId = 0
            packet = None
            packetNumber = 0
            if left == 0 and x == packageNumbers - 1:
                packet, packetNumber = buildPacket('\x02', '\x0F', '\x00\x00',
                                 neighborEMAIL, pChunkedType, buildChunkedPayload(streamId, x, msg, '\x01'), neighborIP, neighborPORT)
            else:
                packet, packetNumber = buildPacket('\x02', '\x0F', '\x00\x00',
                                 neighborEMAIL, pChunkedType, buildChunkedPayload(streamId, x, msg), neighborIP, neighborPORT)
            
            sendPacket(packet, neighborIP, neighborPORT ,packetNumber)
        if left > 0:
            packet, packetNumber = buildPacket('\x02', '\x0F', '\x00\x00',  neighborEMAIL,
                                 pChunkedType, buildChunkedPayload(streamId, packageNumbers, message[packageNumbers*47:], '\x01'), neighborIP, neighborPORT)
            sendPacket(packet, neighborIP, neighborPORT ,packetNumber)
    else:
        packet, packetNumber = buildPacket('\x02', '\x0F',
                             '\x00\x00',  neighborEMAIL, pWholeType, message, neighborIP, neighborPORT)
        sendPacket(packet, neighborIP, neighborPORT ,packetNumber)
    pass

'''
Function which will send the message written in the GUI to the destination.
Also, it can will send the file, if stated.
1) {list_nodes} list all nodes
2) {to_all} broadcast message
3) Decide on packet type depending on encryption
4) Send message, depending on it needs to be chunked or not
'''
def sendMessage(event=None, filePath=''):
    global sock
    message = my_msg.get()

    if message == "{list_nodes}":
        listAllNodes()
        return

    message = '\x01' + message

    if len(filePath) > 0:
        message = open(filePath, 'rb').read()
        message = '\x02' + message

    dest_to = destin_select.get()

    if dest_to == "{to_all}":
        msg_list.insert(END, "me: " + message)
        my_msg.set("")
        if args.encryption: message = Encryption.encrypt(message)
        broadcastMessage(message)
        return

    destHash = md5.new(dest_to).digest()
    kDest = knownTable[destHash]
    msg_list.insert(END, "me: " + message)
    my_msg.set("")
    pChunkedType = '\x0E' if args.encryption else '\x06' 
    pWholeType = '\x0A' if args.encryption else '\x02'
    if args.encryption: message = Encryption.encrypt(message)

    if len(message) > 59:
        left = len(message) % 47
        packageNumbers = (len(message) - left) / 47
        for x in xrange(packageNumbers):
            msg = message[x*47:(x+1)*47]
            streamId = 0
            packet = None 
            packetNumber = 0
            if left == 0 and x == packageNumbers - 1:
                packet, packetNumber = buildPacket('\x02', '\x0F', '\x00\x00',
                                 destHash, pChunkedType, buildChunkedPayload(streamId, x, msg, '\x01'), kDest['IP'], kDest['PORT'])
            else:
                packet, packetNumber = buildPacket('\x02', '\x0F', '\x00\x00',
                                 destHash, pChunkedType, buildChunkedPayload(streamId, x, msg), kDest['IP'], kDest['PORT'])
            sendPacket(packet,  kDest['IP'], kDest['PORT'] ,packetNumber)
        if left > 0:
            packet, packetNumber = buildPacket('\x02', '\x0F', '\x00\x00',  destHash,
                                 pChunkedType, buildChunkedPayload(streamId, packageNumbers, message[packageNumbers*47:], '\x01'), kDest['IP'], kDest['PORT'])
            sendPacket(packet,  kDest['IP'], kDest['PORT'] ,packetNumber)
    else:
        packet, packetNumber = buildPacket('\x02', '\x0F',
                             '\x00\x00',  destHash, pWholeType, message, kDest['IP'], kDest['PORT'])
        sendPacket(packet,  kDest['IP'], kDest['PORT'] ,packetNumber)
    pass


'''
Same as send message, only it will broadcast the message to all nodes.
'''
def broadcastMessage(message):
    pChunkedType = '\x0E' if args.encryption else '\x06' 
    pWholeType = '\x0A' if args.encryption else '\x02'
    for route in minifiedTable:
        if route['destination'] == sourceAddress: continue
        rEMAIL = route['destination']
        rIP = knownTable[rEMAIL]['IP']
        rPORT = knownTable[rEMAIL]['PORT']
        if len(message) > 59:
            left = len(message) % 47
            packageNumbers = (len(message) - left) / 47
            for x in xrange(packageNumbers):
                msg = message[x*47:(x+1)*47]
                streamId = 0
                packet = None 
                packetNumber = 0
                if left == 0 and x == packageNumbers - 1:
                    packet, packetNumber = buildPacket('\x02', '\x0F', '\x00\x00',
                                    rEMAIL, pChunkedType, buildChunkedPayload(streamId, x, msg, '\x01'), rIP, rPORT)
                else:
                    packet, packetNumber = buildPacket('\x02', '\x0F', '\x00\x00',
                                    rEMAIL, pChunkedType, buildChunkedPayload(streamId, x, msg), rIP, rPORT)
                sendPacket(packet,  rIP, rPORT ,packetNumber)
        if left > 0:
            packet, packetNumber = buildPacket('\x02', '\x0F', '\x00\x00',  rEMAIL,
                                 pChunkedType, buildChunkedPayload(streamId, packageNumbers, message[packageNumbers*47:], '\x01'), rIP, rPORT)
            sendPacket(packet,  rIP, rPORT ,packetNumber)
        else:
            packet, packetNumber = buildPacket('\x02', '\x0F',
                                '\x00\x00',  rEMAIL, pWholeType, message, rIP, rPORT)
            sendPacket(packet,  rIP, rPORT ,packetNumber)

'''
Will retransmit packet if ACK is not received in 2 seconds.
Check ttl, if the 16th try, then drop the packet.
'''
def retransmitPacket():
    global sock
    time.sleep(2)
    ackHistoryCopy = copy.deepcopy(ackHistory)
    for dest, _ in ackHistoryCopy.iteritems():
        destIP, destPORT = dest.split(':')
        for pckNum, pckObj  in ackHistoryCopy[dest].iteritems():
            ttl = pckObj['ttl'] + 1
            if ttl >= 16:
                del ackHistory[dest][pckNum]
            else:
                ackHistory[dest][pckNum]['ttl'] += 1 
                sock.sendto(pckObj['packet'], (destIP, int(destPORT)))
            time.sleep(2)
    pass

'''
This will read incoming packets.
1) If DATA (routing or message) or ACK
2) If routing or message
3) If routing then add neighbor if new source and add to routing table, or update the existing routing table 
4) If message then print the message in the GUI
5) If file then create the file. The name of the file is output.file
'''
def parseMessage():
    while True:
        data, addr = sock.recvfrom(100)
        # MESSAGE TYPE 02 = Data, 04 = ACK
        if data[3] == '\x02':
            source = data[8:24]
            destination = data[24:40]

            if sourceAddress != destination:
                routePacket(data, destination)

            if data[40] in ['\x05', '\x0D', '\x01', '\x09']:
                message = ''
                if data[40] in ['\x05', '\x0D']:
                    message = parseChunking(data)
                else:
                    message = data[41:]

                sendAck(data[1:3], source, addr[0], addr[1])
                if message:
                    sendBack = False
                    if not any(d['nextHop'] == source for d in routingTable):
                        msg_list.insert(END, "Neighbor " + knownTable[source]['email'] + " connected")
                        neighbors.append(addr[0] + ":"+ str(addr[1]) + ":" + knownTable[source]['email'])
                        sendBack = True

                    if len(message) == 0 or message == '\x00':
                        neighborToRemove = addr[0] + ":" + str(addr[1]) + ":" + knownTable[source]['email']
                        idx = neighbors.index(neighborToRemove)
                        del neighbors[idx]

                    if data[40] in ['\x0D', '\x09']: message = Encryption.decrypt(message)
                    updateRoutingTable(message, source)
                    if sendBack:
                        sendRoutingTable(addr[0], addr[1], source)
                        

            elif data[40] in ['\x06', '\x0E', '\x02', '\x0A']:
                message = None
                if data[40] in ['\x06', '\x0E']:
                    message = parseChunking(data)
                else:
                    message = data[41:]

                sendAck(data[1:3], source, addr[0], addr[1])   
                if message is not None:

                    if data[40] in ['\x0E', '\x0A']: message = Encryption.decrypt(message)

                    messageType = message[0]
                    message = message[1:]
                    
                    if messageType == '\x02':
                        f = open('output.file', 'wb')
                        f.write(message)
                        f.close()
                        continue

                    from_email = knownTable[source]['email']
                    
                    msg_list.insert(END, from_email + ': ' + message)

        elif data[3] == '\x04':
            dest_addr = addr[0] + ":" + str(addr[1])
            packetConfId = bn(data[5:7])
            if dest_addr in ackHistory and packetConfId in ackHistory[dest_addr]:
                 del ackHistory[dest_addr][packetConfId]
    pass

'''
This function will parse the chunked message, to make sure they are correctly added to each other.
'''
def parseChunking(data):
    if data[42:45] in chunkingHistory:
        if chunkingHistory[data[42:45]]['chunkId'] + 1 == bn(data[45:53]):
            chunkingHistory[data[42:45]]['chunkId'] += 1
            chunkingHistory[data[42:45]]['message'] += data[53:]
            if data[41] == '\x01':
                result = chunkingHistory[data[42:45]]['message']
                del chunkingHistory[data[42:45]]
                return result
    else:
        chunkingHistory[data[42:45]] = {
            'message': data[53:],
            'chunkId': bn(data[45:53])
        }
    pass

'''
This function will route the packet further
'''
def routePacket(data, dest):
    ttl = bn(data[4]) - 1
    if ttl > 0:
        data[4] = nb(ttl, 1)
        if dest in knownTable:
            pckNum = bn(data[1:3])
            sendPacket(data, knownTable[dest]['IP'], knownTable[dest]['PORT'], pckNum)
    pass

'''
This function will update the full routing table.
Also, it will remove the node if the node disconnects.
'''
def updateRoutingTable(message, source):
    global updateTable, routingTable
    if len(message) == 0 or message == '\x00':
        routingTable[:] = [d for d in routingTable if d.get('nextHop') != source or d.get('destination') != source]
        updateTable = True
        retrieveRoutingTable()
    else:
        numberOfRoutes = len(message) / 17
        routingTable[:] = [d for d in routingTable if d.get('nextHop') != source]
        for x in xrange(numberOfRoutes):
            route = message[17*x : 17 * (x+1)]
            cost = bn(route[16])
            email = route[:16]
            if email != sourceAddress:
                routingTable.append({
                    'destination': email,
                    'nextHop': source,
                    'metric': cost + 1
                })
            updateTable = True
        retrieveRoutingTable()
    pass

'''
This function will create a minified routing table, for local processing and for sending it futher to other nodes.
'''
def retrieveRoutingTable():
    global updateTable, routingMessage, minifiedTable
    if updateTable == True:
        minifiedTable = []
        routingMessage = ''
        for route in routingTable:
            if not any(m['destination'] == route['destination'] for m in minifiedTable):
                sameDest = [d for d in routingTable if route['destination'] == d['destination']]
                minCostRoute = min(sameDest, key=lambda x: x['metric'])
                minifiedTable.append(minCostRoute)
                routingMessage += minCostRoute['destination'] + nb(minCostRoute['metric'], 1)
    updateTable = False
    return routingMessage

'''
This function will list all active nodes in the GUI.
'''
def listAllNodes():
    msg_list.insert(END, "List of all active nodes known:")
    for route in minifiedTable:
        email = route['destination']
        msg_list.insert(END, knownTable[email]['email'])
    pass

'''
This function will create a browse window, and once the file selected
it will send it automatically further.
'''
def sendFile(event = None):
    from tkFileDialog import askopenfilename
    filePath = askopenfilename()
    sendMessage(None, filePath)
    return

'''
Send empty table to neighbors, so they would know you disconnected
'''
def disconnect():
    global sock
    for neighbor in neighbors:
        neighborIP, neighborPORT, neighborEMAIL = neighbor.split(':')
        neighborPORT = int(neighborPORT)
        neighborEMAIL = md5.new(neighborEMAIL).digest()
        packet, _ = buildPacket('\x02', '\x0F', '\x00\x00',  neighborEMAIL, '\x01', '\x00', neighborIP, neighborPORT)
        sock.sendto(packet, (neighborIP, neighborPORT))
    return

'''
This function fires when closing the GUI window.
1) Send empty table to all neighbors
2) Destroy GUI window
3) Close socket
'''
def on_closing(event=None):
    disconnect()
    root.destroy()
    sock.close()
    pass

root = Tk()

root.title('Chat App')
message_frame = Frame(root)
my_msg = StringVar()
my_msg.set('Type your message here.')
destin_select = StringVar()
destin_select.set('Destination email')
scrollbar = Scrollbar(message_frame)
msg_list = Listbox(message_frame, height=15,width=50, yscrollcommand=scrollbar.set)
scrollbar.pack(side=RIGHT, fill=Y)
msg_list.pack(side=LEFT, fill=BOTH)
msg_list.pack()
message_frame.pack()

entry_field = Entry(root, textvariable=my_msg)
entry_field.bind("<Return>", sendMessage)
entry_field.pack()
dest_field = Entry(root, textvariable=destin_select)
dest_field.pack()
send_button = Button(root, text="Send", command=sendMessage) #command=send
send_button.pack()
file_button = Button(root, text="Send file", command=sendFile)
file_button.pack()

root.protocol('WM_DELETE_WINDOW', on_closing)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.bind((UDP_IP, UDP_PORT))
init()

receive_thread = Thread(target=parseMessage)
receive_thread.daemon = True
receive_thread.start()

routing_table_thread = Thread(target=broadcastRoutingTable)
routing_table_thread.daemon = True
routing_table_thread.start()

retransmit_thread = Thread(target=retransmitPacket)
retransmit_thread.daemon = True
retransmit_thread.start()
root.mainloop()
