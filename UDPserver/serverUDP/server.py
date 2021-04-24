#!/usr/bin/env python3
import hashlib
import socket, os, sys
import threading, time
import logging, datetime
from interface import *


# Configuracion del servidor
NAME = socket.gethostname()  # Escuchar host
HOST = socket.gethostbyname(NAME) #Devuelve el IP
PORT = 4001  # Puerto primario
PTAV = PORT  # Puerto del thread actual
MSVR = False  # Controllador del server
MSCT = 0  # Contador de conexiones
ESPR = 0  # Contador de clientes esperados
CLTS = []  # Lista de clientes
SOCK = []  # Lista de sockets
ACTV = False  # Control de cliente activo
DWLD = False  # Control cuando descarga


lock1 = threading.Lock()


numThreads = 0  #Number of clients
route = ""  #file path
digest= 0    #the checksum
threads = []  # lista de threads
ports=[]    #client ports

def get_checksum(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    f.close()
    return hash_md5.digest()


def isFile(g_file):
    fileCheck = os.path.isfile(g_file)
    return fileCheck

class ClientThread(threading.Thread):

    def __init__(self, portRef):
        threading.Thread.__init__(self)
        self.digest=digest
        self.clientSock = 0
        self.data = 0
        self.clientAddr = 0
        self.clientPort = PORT + portRef
        self.addr=(HOST, self.clientPort)



# s is the clients soccket
    def ServerGet(self, g_file, s, clientAddr):
        print("In Server, Get function")

        if os.path.isfile(g_file):

            LOG_FILENAME = datetime.datetime.now().strftime("Logs\%Y-%m-%d-%H-%M-%S-log.txt")
            logging.basicConfig(filename=LOG_FILENAME, filemode='w', format='%(asctime)s - %(message)s', level=logging.INFO)

            c = 0
            sizeS = os.stat(g_file)
            sizeSS = sizeS.st_size  # number of packets
            #print("File size in bytes:" + str(sizeSS))
            NumS = int(sizeSS / 4096)
            NumS = NumS + 1
            tillSS = str(NumS)
            tillSSS = tillSS.encode('utf8')
            #envia el numero de paquetes (1)
            s.sendto(tillSSS, clientAddr)

            check = int(NumS)
            GetRunS = open(g_file, "rb")
            # envia los N chunks del archivo (2)
            while check != 0:
                RunS = GetRunS.read(4096)
                s.sendto(RunS, clientAddr)
                c += 1
                check -= 1
                print("Data sending in process:", clientAddr)
            GetRunS.close()
            print("Sent from Server - Get function: Packets:", c)

        else:
            print("Error File does not exist.")


    clientSock = 0
    def getport(self):
        return self.clientPort

    def makeSockClient(self):
        try:
            threads.append(self)
            self.clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            print("+ + + + + + + + + +")
            print("Server socket initialized")
            print('> New Connection: ' + str(HOST) + ' (' + str(self.clientPort) + ') ' + str(len(threads)) + ' times.')
            print("puerto ^ ", self.clientPort, "index ", self.clientPort-4000 , "\n")
        except socket.error:
            print("Failed to create socket")
            sys.exit()


    def verifyClient(self):

        self.clientSock.bind(self.addr)
        data, self.clientAddr = self.clientSock.recvfrom(4096)
        print(self.clientAddr)
        try:
            if (self.clientPort+1000) == self.clientPort:
                print("all working for client: ",self.clientPort-PORT)
        except ValueError:
            print('> BRUH THAT NOT THE PORT\n')
            pass

        print(self.clientAddr)
        print(self.clientPort)

        try:
            txt = data.decode('utf8')
        except ValueError:
            print('> Decryption error.\n')
            pass
        if txt == "Howdy":
            CLTS.append(self.clientAddr)
            ports.append(self.clientAddr)


    def callSend(self):
        self.ServerGet(route, self.clientSock, self.clientAddr)
        # envia el hash digest del archivo (3)
        self.clientSock.sendto(digest, self.clientAddr)
        print("sending File to client ", self.clientPort)


    def run(self):
        # creo que es, cada thread se manda del while, y hace el socket, revisa si el howdy esta bien y le hace send al file y al checksum
        with lock1:
            self.makeSockClient()
        self.verifyClient()
        while numClient < len(CLTS):
            continue
        self.callSend()


while True:
#.\Files\Test1.txt
    try:
        Refresh(ports)
        time.sleep(4)
    except KeyboardInterrupt:
        numClient = int(input("Enter number of clients: "))
        route = input("Enter file path: ")
        if isFile(route):
            print("correct file name .. .. ")
            time.sleep(2)
            digest = get_checksum(route)
            numThreads = numClient
            for i in range(0,numThreads):
                #clientThread = threading.Thread("", i + PORT)
                clientThread = ClientThread(i)
                clientThread.start()

            print("---------------------------")
            print("Press ENTER key to Continue\n")
            input()
        else:
            print("ERROR: File was not found")

    # #############################################################################
    """

    try:
        conn, clientAddr = server.recvfrom(1024)
        print("UDP waiting for:", ESPR - len(CLTS), " conections")

            #newthread = ClientThread(ip, port)
            newthread.start()
            threads.append(newthread)
    except ConnectionResetError:
        print(
            "Error. Port numbers not matching. Exiting. Next time enter same port numbers.")
        sys.exit()
    text = data.decode('utf8')
    #t2 = text.split()
"""
    # The information flow is as follows
    # user specifies number of clients and file path
    # we create as many clientthreads and send the path to it

