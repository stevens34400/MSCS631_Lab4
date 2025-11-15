"""
Lab 4: ICMP Pinger Lab

This program implements a Ping application using ICMP request and reply messages.
Ping is used to test whether a particular host is reachable across an IP network
and measures round-trip time, records packet loss, and prints statistical summaries.

The application sends ICMP echo request packets to a target host and listens for
ICMP echo reply packets. Each message contains a timestamp payload to calculate
round-trip time. After sending each packet, the application waits up to one second
to receive a reply. If one second goes by without a reply, the client assumes the
packet was lost in the network.

Note: This implementation uses raw sockets, which may require administrator/root
privileges on some operating systems.
"""

from socket import *
import os
import sys
import struct
import time
import select

# ICMP Type 8 = Echo Request (ping)
# ICMP Type 0 = Echo Reply (pong)
ICMP_ECHO_REQUEST = 8

def checksum(string):
    """
    Calculate the ICMP checksum for error checking.
    
    The checksum is calculated from the ICMP header + data, with value 0 for the
    checksum field during calculation. This is a standard Internet checksum algorithm
    that adds up 16-bit words and handles carry bits.
    
    Args:
        string: The packet data (header + payload) to calculate checksum for
        
    Returns:
        The 16-bit checksum value in network byte order
    """
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    # Process 16-bit words (2 bytes at a time)
    while count < countTo:
        thisVal = string[count+1] * 256 + string[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    # Handle odd-length strings
    if countTo < len(string):
        csum = csum + string[len(string) - 1]
        csum = csum & 0xffffffff

    # Add carry bits
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    # One's complement
    answer = ~csum
    answer = answer & 0xffff
    # Convert to network byte order
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def receiveOnePing(mySocket, ID, timeout, destAddr):
    """
    Receive an ICMP echo reply packet and calculate the round-trip time.
    
    This function waits up to 'timeout' seconds to receive a reply. It extracts
    the ICMP header from the received IP packet and verifies that it's an echo
    reply (type 0) matching our request ID. The round-trip time is calculated
    by comparing the timestamp in the packet payload with the current time.
    
    ICMP Header Structure (8 bytes):
    - Type (8 bits): 0 for echo reply
    - Code (8 bits): 0 for echo reply
    - Checksum (16 bits): Error checking data
    - ID (16 bits): Identifier to match request with reply
    - Sequence (16 bits): Sequence number
    
    Args:
        mySocket: The raw socket to receive packets on
        ID: The identifier used in the ping request (to match replies)
        timeout: Maximum time to wait for a reply (1 second)
        destAddr: The destination address we pinged
        
    Returns:
        A formatted string with reply information including RTT, or "Request timed out."
    """
    timeLeft = timeout

    while True:
        # Use select to wait for data with a timeout
        startSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        selectDuration = time.time() - startSelect

        # Timeout occurred - no reply received
        if whatReady[0] == []:
            return "Request timed out."

        # Record when we received the packet
        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)

        # Extract IP header (first 20 bytes)
        # The ICMP header starts after the IP header
        ipHeader = recPacket[:20]

        # Extract ICMP header (8 bytes after IP header)
        # ICMP header format: Type (b), Code (b), Checksum (H), ID (H), Sequence (H)
        icmpHeader = recPacket[20:28]
        icmpType, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)

        # Verify this is an echo reply (type 0) and matches our request ID
        if icmpType == 0 and packetID == ID:
            # Extract the timestamp from the packet payload (8 bytes, double precision)
            timeSent = struct.unpack("d", recPacket[28:36])[0]
            # Calculate round-trip time in milliseconds
            rtt = round((timeReceived - timeSent) * 1000, 2)
            # Extract TTL from IP header (byte 8)
            ttl = ipHeader[8]
            # Calculate data size (total packet minus IP header and ICMP header)
            dataSize = len(recPacket) - 28

            # Get the source IP (your machine)
            sender_ip = gethostbyname(gethostname())

            return f"Reply from {destAddr}: bytes={dataSize} time={rtt}ms TTL={ttl} | Pinged from: {sender_ip}"

        # Update remaining time and check if we've exceeded the timeout
        timeLeft -= selectDuration
        if timeLeft <= 0:
            return "Request timed out."


def sendOnePing(mySocket, destAddr, ID):
    """
    Send an ICMP echo request packet to the destination address.
    
    Creates an ICMP echo request packet with:
    - Type: 8 (ICMP_ECHO_REQUEST)
    - Code: 0
    - Checksum: Calculated from header + data
    - ID: Process ID to identify this ping session
    - Sequence: 1 (incremented for each ping)
    - Data: Current timestamp (8 bytes, double precision)
    
    The timestamp in the payload allows us to calculate round-trip time when
    we receive the echo reply.
    
    Args:
        mySocket: The raw socket to send packets on
        destAddr: The destination IP address to ping
        ID: The identifier for this ping session (typically process ID)
    """
    # Start with checksum = 0 for calculation
    checksumValue = 0
    # Pack ICMP header: Type (b), Code (b), Checksum (H), ID (H), Sequence (H)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, checksumValue, ID, 1)
    # Pack current timestamp as payload (8 bytes, double precision)
    data = struct.pack("d", time.time())

    # Calculate checksum on header + data
    checksumValue = checksum(header + data)
    # Convert to network byte order
    checksumValue = htons(checksumValue)

    # Recreate header with correct checksum
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, checksumValue, ID, 1)
    # Combine header and data into complete packet
    packet = header + data

    # Send packet to destination (port 1 is not used for ICMP, but required for sendto)
    mySocket.sendto(packet, (destAddr, 1))


def doOnePing(destAddr, timeout):
    """
    Perform one complete ping operation: send a request and wait for a reply.
    
    Creates a raw socket for ICMP, sends one ping request, waits for the reply,
    and returns the result. The raw socket allows us to send and receive ICMP
    packets directly without using TCP or UDP.
    
    Args:
        destAddr: The destination IP address to ping
        timeout: Maximum time to wait for a reply (1 second)
        
    Returns:
        The result string from receiveOnePing (either reply info or timeout message)
    """
    # Get ICMP protocol number
    icmp = getprotobyname("icmp")
    # Create raw socket for ICMP (requires root/admin privileges)
    # SOCK_RAW allows sending/receiving packets at the IP protocol level
    mySocket = socket(AF_INET, SOCK_RAW, icmp)
    # Use process ID as identifier (masked to 16 bits to fit in ICMP header)
    myID = os.getpid() & 0xFFFF

    # Send the ping request
    sendOnePing(mySocket, destAddr, myID)
    # Wait for and receive the reply
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)

    # Close the socket
    mySocket.close()
    return delay


def ping(host, timeout=1, count=4):
    """
    Main ping function that sends multiple ping requests to a host.
    
    Resolves the hostname to an IP address and sends 'count' ping requests,
    separated by approximately one second. Each ping measures round-trip time
    and records whether the packet was received or timed out.
    
    If one second goes by without a reply, the client assumes that either the
    ping packet or the pong packet was lost in the network (or that the server
    is down).
    
    Args:
        host: Hostname or IP address to ping (e.g., "google.com" or "127.0.0.1")
        timeout: Maximum time to wait for each reply (default: 1 second)
        count: Number of ping requests to send (default: 4)
    """
    # Resolve hostname to IP address
    dest = gethostbyname(host)

    # Show local machine IP at the top
    local_ip = gethostbyname(gethostname())
    print(f"Pinging {dest} using Python (from your IP: {local_ip}):\n")

    # Send ping requests separated by approximately one second
    for i in range(count):
        print(doOnePing(dest, timeout))
        time.sleep(1)  # Wait one second between pings


if __name__ == "__main__":
    """
    Test the pinger application.
    
    First test with localhost (127.0.0.1), then test across the network
    by pinging servers in different continents as required by the assignment.
    """
    print("Pinging google.com")
    ping("google.com", count=4)
    # Uncomment to test pinging servers in different continents:
    # print("Pinging bbc.co.uk")
    # ping("bbc.co.uk", count=4)
    # print("Pinging japan.go.jp")
    # ping("japan.go.jp", count=4)
    # print("Pinging cs.anu.edu.au")
    # ping("cs.anu.edu.au", count=4)
