from socket import *
from constants import *
from secrets import randbits
from base64 import urlsafe_b64encode


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

    def handshake(self) -> bytes:
        if self.__socket != None:
            lines, message = self.receive()
            message = message.decode()

            if lines[0].find(HANDSHAKE) != -1:
                message = message.split('&')
                p = int(message[0][2:])
                g = int(message[1][2:])

                A = int(message[2][2:])

                b = randbits(GEN_BITS)
                B = pow(g, b, p)

                content = f"B={B}"

                terms = []
                terms.append(f"{RESPONSE} 200 {OK}{CRLF}")
                terms.append(f"{CONTENT_LENGTH}{len(content)}{CRLF}")
                terms.append(CRLF)
                terms.append(content)

                self.send(terms)

                K = pow(A, b, p)
                K = K.to_bytes((K.bit_length() + 7) // 8, 'little')
                if len(K) < FERNET_KEYSIZE:
                    K += b'\xcc' * (FERNET_KEYSIZE - len(K))
                else:
                    K = K[:FERNET_KEYSIZE]

                return urlsafe_b64encode(K)
        return b""

    def close(self):
        if self.__socket != None:
            try:
                self.__socket.close()
            except:
                pass

    def send(self, strings: list):
        if self.__socket != None:
            for string in strings:
                if isinstance(string, str):
                    string = string.encode()
                self.__socket.send(string)

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

        # data_message = data_message.decode()
        return lines, data_message