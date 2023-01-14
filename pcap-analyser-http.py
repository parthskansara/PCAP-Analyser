
import dpkt
import struct
import math


def unPack(buffer, fmt, pos, size):
    if(len(buffer) > pos):
        return str(struct.unpack(fmt, buffer[pos:pos+size])[0])
    else: pass

class Packet:
	def parse(self, timestamp, buffer):
            #https://docs.python.org/2/library/struct.html
            # >B is used for u signed characters, so integer in python
            # >H is used for unsigned short
            self.buffer=buffer
            self.timestamp = timestamp
            self.size = len(buffer)
            head_len = int.from_bytes(buffer[46:47], byteorder='big')
            self.head_len = 4*(head_len>>4)
            self.srcIp = unPack(buffer, ">B", 26, 1) + "." + unPack(buffer, ">B", 27, 1) + "." + unPack(buffer, ">B", 28, 1) + "." + unPack(buffer, ">B", 29, 1)
            self.destIp = unPack(buffer, ">B", 30, 1) + "." + unPack(buffer, ">B", 31, 1) + "." + unPack(buffer, ">B", 32, 1) + "." + unPack(buffer, ">B", 33, 1)
            self.sPort = int.from_bytes(self.buffer[34:36], byteorder='big')
            self.dPort = int.from_bytes(self.buffer[36:38], byteorder='big')
            synack = "{0:16b}".format(int(unPack(buffer, ">H", 46, 2)))
            self.syn = synack[14]
            self.ack = synack[11]
            self.seqNumber = int.from_bytes(self.buffer[38:42], byteorder='big')
            self.ackNumber = int.from_bytes(self.buffer[42:46], byteorder='big')
            self.wndsize = int.from_bytes(self.buffer[48:50], byteorder='big')
            self.payload     = self.buffer[34+self.head_len:]
            self.payload_len = len(self.payload)

class initializePorts:
  
    sPort = ""
    dPort = ""
    packets = []
    def __init__(self, sourcePort, destinationPort):
        self.sPort = sourcePort
        self.dPort = destinationPort
		

def readPCAPFile(pcap):

    totalFlows = []
    count = 0
    for timestamp, buffer in pcap:
        packets = Packet()
        packets.parse(timestamp, buffer)
        
        totalFlows.append(packets) 
 
    return totalFlows

def getTransactions(totalFlows):

    flows = []

    for packet in totalFlows:

        if packet.syn == "1" and packet.ack == "0":
            connection = initializePorts(packet.sPort, packet.dPort)
            connection.packets = []     
            flows.append(connection)

    for packet in totalFlows:
        for c in range(0,len(flows)):
            if (((packet.sPort == flows[c].sPort) and (packet.dPort == flows[c].dPort)) or ((packet.sPort == flows[c].dPort) and (packet.dPort == flows[c].sPort))):
                flows[c].packets.append(packet)

    return flows

    
def reAssemble(flow):
    ackFinal = 0
    payloadACK = 0
    for packet in flow:
        
        if "GET" in str(packet.payload):               
            ackFinal = packet.payload_len + packet.seqNumber           
            print("Request: ", packet.payload, "\nSource Port, Destination Port, Sequence Number, Ack Number")

            row = (packet.sPort, packet.dPort,packet.seqNumber, packet.ackNumber)
            print(row[0],"\t",row[1],"\t",row[2], "\t", row[3])
            print("\nSource Port, Destination Port, Sequence Number, Ack Number")
            
            
        elif packet.payload_len > 0 and ackFinal == packet.ackNumber:          
            if "HTTP" in str(packet.payload): 
              payloadACK = packet.payload   

            row = (packet.sPort, packet.dPort, packet.seqNumber, packet.ackNumber)
            print(row[0],"\t",row[1],"\t",row[2], "\t", row[3])

        
def identifyHTTP(totalTransactions1080,totalTransactions1081,totalTransactions1082):
    a, b, c = 1, 1, 1

    print("At Port 8080:\n")

    for t in totalTransactions1080:
        print("Flow {} -> From: ".format(a), t.sPort, " to: ", t.dPort)
        a+=1

    print("\nThere are 18 flows in 1080, which points to HTTP 1.0.\nIt is a non-persistent connection, where every object is fetched via a new connection.\n")

    print("At Port 8081:\n")
    
    for t in totalTransactions1081:
        print("Flow {} -> From: ".format(b), t.sPort, " to: ", t.dPort)
        b+=1

    print("\nThere are 6 flows in 1081, which points to an establishment of a parallel connection.\nThus, it is follows HTTP 1.1.\n")

    print("At Port 8082:\n")

    for t in totalTransactions1082:
        print("Flow {} -> From: ".format(c), t.sPort, " to: ", t.dPort)
        c+=1

    print("\nThere are only 2 flows in 1082 through which all objects are fetched.\nThis indicates a persistent TCP connection, which might have been disrupted in between due to page refresh.\nThis is clearly an HTTP 2.0 connection.\n")
    

def findMinMax (arr):
  new_arr = arr.copy()
  new_arr.sort()
  min = new_arr[0]
  minIndex = arr.index(min)

  max = new_arr[-1]
  maxIndex = arr.index(max)

  return min, max, minIndex, maxIndex

    
def results(files_list):
    time = []
    packets = []
    rawBytes = []
    
    for i in files_list:
        time.append(calculateTime(i))
        packets.append(countPacketsPerVersion(i))
        rawBytes.append(bytesSent(i))

    minTime, maxTime, minTIndex, maxTIndex = findMinMax(time)
    minP, maxP, minPIndex, maxPIndex = findMinMax(packets)
    minRB, maxRB, minRBIndex, maxRBIndex = findMinMax(rawBytes)
    
    print("Printing Results:")
    
    inferredProtocol = ["HTTP 1.0", "HTTP 1.1", "HTTP 2.0"]


    for i in range(3):
      print("\n",inferredProtocol[i])
      print("Load Time: ", time[i])
      print("Packets Sent: ", packets[i])
      print("Number of raw bytes: ", rawBytes[i])
    
    print("\nFastest Load Time: ", inferredProtocol[minTIndex], " -> ", minTime, " seconds")
    print("Slowest Load Time: ", inferredProtocol[maxTIndex], " -> ", maxTime, " seconds")

    print("\nMax Packets: ", inferredProtocol[maxPIndex], " -> ", maxP)
    print("Min Packets: ",  inferredProtocol[minPIndex], " -> ", minP)

    print("\nMax raw bytes: ", inferredProtocol[maxRBIndex], " -> ", maxRB)
    print("Min raw bytes: ", inferredProtocol[minRBIndex], " -> ", minRB)



def calculateTime(total):
    time_diff = total[-1].timestamp - total[0].timestamp
    return time_diff

def countPacketsPerVersion(total):
    pcount = 0
    for packet in total:
        if packet.sPort in [1080,1081,1082]:        
            pcount += 1
    return pcount


def bytesSent(total):
    tot_bytes = 0
    for packet in total:
        if packet.sPort in [1080,1081,1082]:      
            tot_bytes += packet.size
    return tot_bytes


def main():
    file1080 = open('http_1080.pcap', 'rb')
    file1081 = open('http_1081.pcap', 'rb')
    file1082 = open('http_1082.pcap', 'rb')
    
    pcap1080 = dpkt.pcap.Reader(file1080)
    pcap1081 = dpkt.pcap.Reader(file1081)
    pcap1082 = dpkt.pcap.Reader(file1082)

    count = 0
    totalFlows1080 = readPCAPFile(pcap1080)
    totalFlows1081 = readPCAPFile(pcap1081)
    totalFlows1082 = readPCAPFile(pcap1082)
    file_list = [totalFlows1080, totalFlows1081, totalFlows1082]

    totalTransactions1080 = getTransactions(totalFlows1080)
    totalTransactions1081 = getTransactions(totalFlows1081)
    totalTransactions1082 = getTransactions(totalFlows1082)
    
    flowCount=1

    for fl in totalTransactions1080:
        print("Flow {}:".format(flowCount))
        flowCount += 1
        reAssemble(fl.packets)
        print("-"*50)
       
    identifyHTTP(totalTransactions1080,totalTransactions1081,totalTransactions1082)
    
    results(file_list)


if __name__ == '__main__':
	main()