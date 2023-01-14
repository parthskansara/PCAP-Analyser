import dpkt
import struct
import math
from tkinter import filedialog as fd

#Reference : https://pymotw.com/2/struct/
senderIP = "130.245.145.12"
receiverIP = "128.208.2.198"

class Packet:
  validity = True
  headerSize = ""
  sourceIP = ""
  destIp = ""
  srcPort = ""
  destPort = ""
  syn = ""
  ack = ""
  wndsize = ""
  seqNum = ""
  ackNum = ""
  size = ""
  timestamp = 0
  mss = ""

  #Reference : http://www.networksorcery.com/enp/protocol/tcp.htm
  def parse(self, timestamp, buffer):
    try:
      self.headerSize = unPack(buffer, ">B", 46, 1)
      self.sourceIP = unPack(buffer, ">B", 26, 1) + \
              "." + unPack(buffer, ">B", 27, 1) + \
              "." + unPack(buffer, ">B", 28, 1) + \
              "." + unPack(buffer, ">B", 29, 1)

      self.destIp = unPack(buffer, ">B", 30, 1) + \
              "." + unPack(buffer, ">B", 31, 1) + \
              "." + unPack(buffer, ">B", 32, 1) + \
              "." + unPack(buffer, ">B", 33, 1)

      self.srcPort = unPack(buffer, ">H", 34, 2)
      self.destPort = unPack(buffer, ">H", 36, 2)
      option = "{0:16b}".format(int(unPack(buffer, ">H", 46, 2)))
      self.syn = option[14]
      self.ack = option[11]
      self.seqNum = unPack(buffer, ">I", 38, 4)
      self.ackNum = unPack(buffer, ">I", 42, 4)
      self.wndsize = unPack(buffer, ">H", 48, 2)
      self.size = len(buffer)
      self.timestamp = timestamp
      self.mss = unPack(buffer, ">H", 56, 2)
    except:
      self.validity = False


class Connection:
	srcPort = ""
	destPort = ""
	packets = []
	def __init__(self, _src, _dest):
		self.srcPort = _src
		self.destPort = _dest

def ParseConnections(data):
	connections = []
	count = 0

	for packet in data:
		count += 1
		if packet.syn == "1" and packet.ack == "1":
			# print str(packet.srcPort) + ":" + str(packet.destPort) 
			connection = Connection(packet.srcPort, packet.destPort)
			connection.packets = []     
			connections.append(connection)

	# print len(connections)
	# print count
	# for conn in connections:
	# 	print str(conn.srcPort) + ":" + str(conn.destPort) + ":" + str(len(conn.packets)) 

	for packet in data:
		for c in range(0,len(connections)):
			if (((packet.srcPort == connections[c].srcPort) and (packet.destPort == connections[c].destPort)) or ((packet.srcPort == connections[c].destPort) and (packet.destPort == connections[c].srcPort))):
				connections[c].packets.append(packet)
 
	# for c in range(0,len(connections)):
	# 	print str(connections[c].srcPort) + ":" + str(connections[c].destPort) + ":" + str(len(connections[c].packets)) 
	return connections

def unPack(buffer, format, position, size):
  if (position < len(buffer)):
    return str(struct.unpack(format, buffer[position:position+size])[0])
  else:
    return "This is not a valid packet."

def readPCAPFile(pcap):
	data = []
	for timestamp, buffer in pcap:
		packet = Packet()
		packet.parse(timestamp, buffer)
    #We check validity of the packet before appending it to data
		if packet.validity:	
			data.append(packet)
 
	return data

def getValues (conn):
  transactions = {}
  counter = 2
  print("Sender to Receiver: \n")
  print("Packet 1: SEQ - ",conn.packets[3].seqNum, " ACK - ", conn.packets[3].ackNum, " WND - ", conn.packets[3].wndsize)
  print("Packet 2: SEQ - ",conn.packets[4].seqNum, "ACK - ", conn.packets[4].ackNum, " WND - ", conn.packets[4].wndsize)
  a = conn.packets[3].ackNum
  b = conn.packets[4].ackNum
  count = 0
  print("\nReceiver to Sender: ")
  for c in conn.packets[5:]:
    if c.seqNum == a or c.seqNum == b:
      print("Packet ", count+1, ": ", "SEQ - ", c.seqNum, "ACK - ", c.ackNum, "WND - ", c.wndsize)
      count+=1

      if count == 2:
        break

def getTransactionDetails(connections):
  print("\n2. Transaction Details (2 per TCP connection): ") 
  for connection in connections:
    
    print("\n> Connecting " + connection.srcPort + " to " + connection.destPort + " ----")
    getValues(connection)

def findThroughput(data):
  flag = 0
  totalPayloadSize = 0
  firstPacket = 0
  lastPacket = 0

  for packet in data:
    if packet.sourceIP == senderIP:
      totalPayloadSize += int(packet.size)

      if flag == 0:
        flag = 1
        firstPacket = packet.timestamp

      lastPacket = packet.timestamp

  print("\n3. Throughput : " + str(totalPayloadSize/((lastPacket-firstPacket)*10**6)), " MBps")

def computeLossRate(data):

  packetLoss = 0
  totalPackets = 0

  sequence = {}
  
  for packet in data:
    if packet.sourceIP == senderIP and packet.destIp == receiverIP:
      sequence[packet.seqNum] = sequence.get(packet.seqNum,0) + 1
      totalPackets += 1

  for key, value in sequence.items():
    if key in sequence:
      packetLoss += sequence[key]-1

  packetLoss -= 1
  lossRate = packetLoss / totalPackets

  return packetLoss, lossRate

  # print("\n4. Packets Lost : " + str(packetLoss-1))
  # print("Loss Rate : " + str((packetLoss-1)/totalPackets))


def calculateRTT(data, loss):

  alpha = 0.125
  payLoad = 1448

  sequence = {}
  ack = {}
  retransmitted = {}

  oldPacket = data[0]
  newPacket = data[1]

  oldRTT = newPacket.timestamp - oldPacket.timestamp

  for packet in data[2:]:
    if packet.sourceIP == senderIP and packet.destIp == receiverIP:
      sequence[packet.seqNum] = packet

      if packet.seqNum in retransmitted.keys():
        retransmitted[packet.seqNum] += 1

      else:
        retransmitted[packet.seqNum] = 1

    else:
      ack[packet.ackNum] = packet

  
  for a, b in ack.items():
    c = int(a) - payLoad

    if c in retransmitted.keys() and retransmitted == 1:
      newRTT = b.timestamp - sequence[c].timestamp
      oldRTT = alpha * newRTT + (1 - alpha)* oldRTT
        
  try:
    mss = 1460
    print(mss)
    print(oldRTT)
    print(loss)
    tp = (math.sqrt(3/2)*mss)/(10**6*oldRTT * math.sqrt(loss))
    
    print("\n5. Round Trip Time: ", oldRTT, " seconds")
    print("Theoretical Throughput: ", tp, " MBps")
    return(oldRTT, tp)

  except ZeroDivisionError as ze:
    print("\n5. Round Trip Time: ", oldRTT, " seconds")
    print("Theoretical Throughput Error: Infinity (division by zero)")
    return(oldRTT, "Infinity (Division by zero)")
  


def retransmissions(data):

  sequence = {}
  ack = {}

  for packet in data:
    
    if packet.sourceIP == senderIP and packet.destIp == receiverIP:
      sequence[packet.seqNum] = sequence.get(packet.seqNum,0) + 1

    elif packet.sourceIP == receiverIP and packet.destIp == senderIP:
      ack[packet.ackNum] = ack.get(packet.ackNum,0) + 1

  loss = 0
  tdaLoss = 0

  for key, value in sequence.items():
    if key in sequence:
      loss += sequence[key]-1
    
    if (key in ack) and (ack[key] > 2):
      tdaLoss += sequence[key]-1

  loss -=1

  print("\n6. Retransmission of duplicate packets : " + str(loss))
  print("Packets retransmitted due to Triple Ack Loss: " + str(tdaLoss))
  print("Packets retransmitted due to timeout: " + str(loss -tdaLoss))


def congestionWindow(data):
  count = 0
  cwnd = []
  cwndCount = []
  
  loss = computeLossRate(data)[1]
  rtt, tp = calculateRTT(data, loss)
  t1 = data[0].timestamp 

  for packet in data:
    
    if packet.timestamp < t1 + rtt:
      count += 1
    
    else:
      cwnd.append(count)
      count = 0
      t1 = packet.timestamp

    if len(cwnd) == 10: break

  print("Congestion Window: ", cwnd)
  

def main():

  file = fd.askopenfilename()
  pcap = dpkt.pcap.Reader(file)

  count = 0
  data = readPCAPFile(pcap)

  #Find number of connections
  connections = ParseConnections(data)

  print ("1. Number of TCP flows initiated by the sender: " + str(len(connections)))
  for c in range(len(connections)):
    print(str(connections[c].srcPort) + ":" + str(connections[c].destPort) + ":" + str(len(connections[c].packets)) )

  #Part 2(a.)
  getTransactionDetails(connections)

  for conn in connections:
    #Part 2(b.)
    findThroughput(conn.packets)

  for conn in connections:

    #Part 2(c.)
    packetLoss, lossRate = computeLossRate(conn.packets)
    print("\n4. Packets Lost: ", packetLoss)
    print("Loss Rate: ", lossRate)

    calculateRTT(conn.packets, lossRate)


  # for conn in connections:

  #   #Part 2(d.)
  #   for i in lossRate:
  #     calculateRTT(conn.packets, i)

  for conn in connections:

    retransmissions(conn.packets)

    congestionWindow(conn.packets)

    print("-------------------------------------------------------------------------------")

if __name__ == '__main__':
	main()