import socket, argparse, md5, os, time, copy
from encryption import Encryption
from threading import Thread
from utils import bitstring_to_bytes, nb, bn
from Tkinter import *

#, default=["127.0.0.1:9999:akim.essen@ttu.ee"]
parser = argparse.ArgumentParser(description='Network Protocol built on UDP')
parser.add_argument('-p', '--port', default=9999, type=int,
                    help='Port to listen (default 9999)')
parser.add_argument('-n', '--neighbors', default=[], nargs='+', help='Neighbors IP and Ports')
parser.add_argument(
    '-e', '--email', default="akim.essen@ttu.ee", help="TTU email")
parser.add_argument('-k', '--known', default=['127.0.0.1:9999:akim.essen@ttu.ee', '127.0.0.1:9998:essen@ttu.ee', '127.0.0.1:9997:test@ttu.ee'], nargs='+', help='Known list of nodes')
parser.add_argument('-en', '--encryption', default=True, type=bool, help='Enable Encryption')

args = parser.parse_args()

# global variables
updateTable = True
version = '\x01'
sourceAddress = md5.new(args.email).digest()
routingTable = []
routingMessage = ''
emailIPtable = {}
knownTable={}
chunkingHistory = {}
ackHistory = {}
neighbors = args.neighbors

UDP_IP = '127.0.0.1'
UDP_PORT = args.port


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

    for neighbor in neighbors:
        neighborIP, neighborPORT, neighborEMAIL = neighbor.split(':')
        neighborPORT = int(neighborPORT)
        neighborEMAIL = md5.new(neighborEMAIL).digest()
        routingTable.append({
            'destination': neighborEMAIL,
            'nextHop': neighborEMAIL,
            'metric': 1
        })
        sendRoutingTable(neighborIP, neighborPORT, neighborEMAIL)
    pass


def buildPacket(packetType, ttl, confID, destAdd, layer4Type, payload, dIP, dPORT):
    packetNumber = 0
    if destAdd in ackHistory:
        while packetNumber in ackHistory[dIP + ":" + str(dPORT)]:
            packetNumber += 1
    layer3 = version + nb(packetNumber, 2) + packetType + \
        ttl + confID + '\x00' + sourceAddress + destAdd
    packet = layer3 + layer4Type + payload
    return packet, packetNumber


def sendAck(packetNumber, destinationAddress, nIP, nPORT):
    global sock
    packet, _ = buildPacket('\x04', nb(15,1), packetNumber, '\x00', sourceAddress, destinationAddress, nIP, nPORT)
    print nIP, nPORT
    sock.sendto(packet, (nIP, nPORT))
    pass

def buildChunkedPayload(streamId, chunkId, payload, status='\x00'):
    return status + nb(streamId, 3) + nb(chunkId, 8) + payload


def broadcastRoutingTable():
    while True:
        for neighbor in neighbors:
            neighborIP, neighborPORT, neighborEMAIL = neighbor.split(':')
            neighborPORT = int(neighborPORT)
            neighborEMAIL = md5.new(neighborEMAIL).digest()
            sendRoutingTable(neighborIP, neighborPORT, neighborEMAIL)
        time.sleep(30)
    pass

def sendPacket(packet, neighborIP, neighborPORT, packetNumber):
    dest = neighborIP + ":" + str(neighborPORT)
    if dest not in ackHistory:
        ackHistory[dest] = {}
    ackHistory[dest][packetNumber] = {
        'packet': packet,
        'ttl': 0
    }
    sock.sendto(packet, (neighborIP, neighborPORT))

def sendRoutingTable(neighborIP, neighborPORT, neighborEMAIL):
    message = retrieveRoutingTable()
    if args.encryption: message = Encryption.encrypt(message)
    print "Send message length: " + str(len(message))
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
                                 neighborEMAIL, '\x09', buildChunkedPayload(streamId, x, msg, '\x01'), neighborIP, neighborPORT)
            else:
                packet, packetNumber = buildPacket('\x02', '\x0F', '\x00\x00',
                                 neighborEMAIL, '\x09', buildChunkedPayload(streamId, x, msg), neighborIP, neighborPORT)
            
            sendPacket(packet, neighborIP, neighborPORT ,packetNumber)
        if left > 0:
            packet, packetNumber = buildPacket('\x02', '\x0F', '\x00\x00',  neighborEMAIL,
                                 '\x09', buildChunkedPayload(streamId, packageNumbers, message[packageNumbers*47:], '\x01'), neighborIP, neighborPORT)
            sendPacket(packet, neighborIP, neighborPORT ,packetNumber)
    else:
        packet, packetNumber = buildPacket('\x02', '\x0F',
                             '\x00\x00',  neighborEMAIL, '\x01', message, neighborIP, neighborPORT)
        sendPacket(packet, neighborIP, neighborPORT ,packetNumber)
    #packet = buildPacket('\x00\x01', '\x02', '\x0F', '\x00\x00',neighborEMAIL, '\x01', message)
    #sock.sendto(packet, (neighborIP, neighborPORT))
    pass


def sendMessage(event=None):
    global sock
    message = my_msg.get()
    dest_to = destin_select.get()
    destHash = md5.new(dest_to).digest()
    kDest = knownTable[destHash]
    msg_list.insert(END, "me: " + message)
    my_msg.set("")
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
                                 destHash, '\x0A', buildChunkedPayload(streamId, x, msg, '\x01'), kDest['IP'], kDest['PORT'])
            else:
                packet, packetNumber = buildPacket('\x02', '\x0F', '\x00\x00',
                                 destHash, '\x0A', buildChunkedPayload(streamId, x, msg), kDest['IP'], kDest['PORT'])
            sendPacket(packet,  kDest['IP'], kDest['PORT'] ,packetNumber)
        if left > 0:
            packet, packetNumber = buildPacket('\x02', '\x0F', '\x00\x00',  destHash,
                                 '\x0A', buildChunkedPayload(streamId, packageNumbers, message[packageNumbers*47:], '\x01'), kDest['IP'], kDest['PORT'])
            sendPacket(packet,  kDest['IP'], kDest['PORT'] ,packetNumber)
    else:
        packet, packetNumber = buildPacket('\x02', '\x0F',
                             '\x00\x00',  destHash, '\x02', message, kDest['IP'], kDest['PORT'])
        sendPacket(packet,  kDest['IP'], kDest['PORT'] ,packetNumber)
    pass
# encrypted 00001000
# chunked   00000100
# data      00000010
# routing   00000001

def retransmitPacket():
    global sock
    time.sleep(2)
    ackHistoryCopy = copy.deepcopy(ackHistory)
    for dest, _ in ackHistoryCopy.iteritems():
        destIP, destPORT = dest.split(':')
        for pckNum, pckObj  in ackHistoryCopy[dest].iteritems():
            print pckNum, pckObj
            ttl = pckObj['ttl'] + 1
            if ttl >= 16:
                del ackHistory[dest][pckNum]
            else:
                ackHistory[dest][pckNum]['ttl'] += 1 
                sock.sendto(pckObj['packet'], (destIP, int(destPORT)))
            time.sleep(2)
    pass


def parseMessage():
    while True:
        data, addr = sock.recvfrom(100)

        # MESSAGE TYPE 02 = Data, 04 = ACK
        if data[3] == '\x02':
            source = data[8:24]
            destination = data[24:40]

            if sourceAddress != destination:
                routePacket(data, destination)

            if data[40] == '\x01' or data[40] == '\x09':
                print 'routing full'
                message = ''
                if data[40] == '\x09':
                    message = parseChunking(data)
                else:
                    message = data[41:]

                #address = addr[0] + ':' + str(addr[1])
                sendAck(data[1:3], source, addr[0], addr[1])
                if message:
                    sendBack = False
                    if not any(d['nextHop'] == source for d in routingTable):
                        msg_list.insert(END, "Neighbor " + knownTable[source]['email'] + " connected")
                        neighbors.append(addr[0] + ":"+ str(addr[1]) + ":" + knownTable[source]['email'])
                        sendBack = True
                        
                    print "Received message length: " + str(len(message))
                    if args.encryption: message = Encryption.decrypt(message)
                    updateRoutingTable(message, source)
                    if sendBack:
                        sendRoutingTable(addr[0], addr[1], source)
                        

            elif data[40] == '\x02' or data[40] == '\x0A':
                print 'data'
                message = None
                if data[40] == '\x0A':
                    message = parseChunking(data)
                else:
                    message = data[41:]
                if message is not None:
                    from_email = knownTable[source]['email']
                    print "Received message length: " + str(len(message))
                    if args.encryption: message = Encryption.decrypt(message)
                    msg_list.insert(END, from_email + ': ' + message)
                    sendAck(data[1:3], source, addr[0], addr[1])
            elif data[40] == '\x08':
                print 'encrypted'

        elif data[3] == '\x04':
            print "ACK"
            dest_addr = addr[0] + ":" + str(addr[1])
            packetConfId = bn(data[5:7])
            if dest_addr in ackHistory and packetConfId in ackHistory[dest_addr]:
                 del ackHistory[dest_addr][packetConfId]
    pass

def parseChunking(data):
    if data[42:45] in chunkingHistory:
        if chunkingHistory[data[42:45]]['chunkId'] + 1 == bn(data[45:53]):
            chunkingHistory[data[42:45]]['chunkId'] += 1
            chunkingHistory[data[42:45]]['message'] += data[53:]
            print data[41] == '\x01'
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

def routePacket(data, dest):
    ttl = bn(data[4]) - 1
    if ttl > 0:
        data[4] = nb(ttl, 1)
        if dest in knownTable:
            pckNum = bn(data[1:3])
            sendPacket(data, knownTable[dest]['IP'], knownTable[dest]['PORT'], pckNum)

    pass


def updateRoutingTable(message, source):
    global updateTable
    # ADD TO TABLE
    numberOfRoutes = len(message) / 17
    # if source in routingTable:
    #     routingTable[source] = []
    for x in xrange(numberOfRoutes):
        cost = bn(message[16 * (x+1)])
        email = message[:16 * (x+1)]
        check = [r for r in routingTable if r['destination']
                 == email and r['nextHop'] == source]
        if len(check) > 0 and check[0]['metric'] > cost:
            idx = routingTable.index(check[0])
            del routingTable[idx]
            routingTable.append({
                'destination': email,
                'nextHop': source,
                'metric': cost + 1
            })
            updateTable = True
        elif len(check) == 0:
            routingTable.append({
                'destination': email,
                'nextHop': source,
                'metric': cost + 1
            })
            updateTable = True
        # routingTable[source].append([email, cost, priority])
    #print routingTable
    pass


def retrieveRoutingTable():
    global updateTable, routingMessage
    minifiedTable = []
    if updateTable == True:
        routingMessage = ''
        for route in routingTable:
            if not any(m['destination'] == route['destination'] for m in minifiedTable):
                sameDest = [
                    d for d in routingTable if route['destination'] == d['destination']]
                minCostRoute = min(sameDest, key=lambda x: x['metric'])
                minifiedTable.append(minCostRoute)
                routingMessage += minCostRoute['destination'] + \
                    nb(minCostRoute['metric'], 1)
    updateTable = False
    return routingMessage

def on_closing(event=None):
    sock.close()
    root.quit()

root = Tk()

root.title('Chat App')
message_frame = Frame(root)
my_msg = StringVar()
my_msg.set('Type your message here.')
destin_select = StringVar()
destin_select.set('Destination ip:port')
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

root.protocol('WM_DELETE_WINDOW', on_closing)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.bind((UDP_IP, UDP_PORT))
init()

receive_thread = Thread(target=parseMessage)
receive_thread.start()

routing_table_thread = Thread(target=broadcastRoutingTable)
routing_table_thread.start()

retransmit_thread = Thread(target=retransmitPacket)
retransmit_thread.start()
root.mainloop()
