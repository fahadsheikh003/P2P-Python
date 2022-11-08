from socket import *
from constants import *

class TTPClient:
    def __init__(self) -> None:
        self.__socket = None

    def connect(self) -> bool:
        self.__socket = socket(AF_INET, SOCK_STREAM)
        try:
            self.__socket.connect((TTP_IP, TTP_PORT))
            return True
        except:
            self.__socket = None
            return False

    def close(self):
        if self.__socket != None:
            try:
                self.__socket.close()
            except:
                pass

    def send(self, strings: list):
        if self.__socket != None:
            for string in strings:
                self.__socket.send(string.encode())

    def receive(self) -> tuple:
        if self.__socket == None:
            return None, None

        messege = self.__socket.recv(BUFFER_SIZE)
        while "\r\n\r\n".encode() not in messege and len(messege) > 0:
            messege += self.__socket.recv(BUFFER_SIZE)

        text_messege, crlf, data_message = messege.partition("\r\n\r\n".encode())

        # Divide text part into lines
        lines = text_messege.decode().split("\r\n")

        content_length = None

        # Find if the value of content length is provided
        for line in lines:
            if "Content-Length: " in line:
                content_length = int(line[16:])

        if content_length != None:
            # Keep reading data message until the number of bytes indicated by content length is received
            while content_length-len(data_message) > 0:
                data_message += self.__socket.recv(BUFFER_SIZE)

        data_message = data_message.decode()
        
        return lines, data_message