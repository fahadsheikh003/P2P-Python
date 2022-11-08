from tkinter import Tk, Canvas, Entry, Button, messagebox, LabelFrame, Label, Listbox, Text
from socket import *
from PIL import ImageTk, Image
from _thread import start_new_thread
from concurrent.futures import ThreadPoolExecutor
from os import mkdir
from cryptography.fernet import Fernet
from multiprocessing import Process

from constants import *
from utils import *
from ttp_client import TTPClient
from rsa import encrypt, decrypt

class App:
    def __init__(self) -> None:

        try: 
            mkdir(KEY_DIRECTORY) 
        except: 
            pass

    def chatbox(self, sock: socket, rusername):
        box_index = 1
        
        def on_closing():
            try:
                sock.shutdown(SHUT_RDWR)
                sock.close()
            except: pass

            try: app.destroy()
            except: pass

        def fetch_key() -> bool:
            with open(f"{KEY_DIRECTORY}/{PRIAVTE_KEY}", 'r') as f:
                terms = f.read().split('\n')

            username = terms[0]
            password = terms[1]

            ttp = TTPClient()

            if not ttp.connect():
                messagebox.showerror("Error", "Unable to connect to the server!")
                return False

            key = ttp.handshake()
            cipher = Fernet(key)

            content = f"username={username}&password={password}&rusername={rusername}"
            encrypted_content = cipher.encrypt(content.encode())

            terms = []
            terms.append(GET + " " + KEY + CRLF)
            terms.append(CONTENT_LENGTH + str(len(encrypted_content)) + CRLF)
            terms.append(CRLF)
            terms.append(encrypted_content)

            ttp.send(terms)
            terms, data_messege = ttp.receive()

            if terms == None:
                messagebox.showerror("Error", "Unable to receive any response from server!")
                return False

            elif terms[0].find(f"200 {OK}") != -1:
                data_messege = cipher.decrypt(data_messege)
                data_messege = data_messege.decode()

                parameters = data_messege.split('&')
                e = parameters[0][2:]
                n = parameters[1][2:]

                with open(f"{KEY_DIRECTORY}/{PUBLIC_KEY}{rusername}", 'w') as f:
                    f.write(f"{e}\n{n}")

                # messagebox.showinfo("Success", f"Public Key of User: {rusername} fetched Successfully")

            elif terms[0].find(f"401 {BAD_REQUEST}") != -1:
                messagebox.showerror("Error", f"Unable to find {rusername}!")
                return False

            else:
                messagebox.showerror("Error", "An unknown error occured!")
                return False

            ttp.close()

            return True

        def receive_messages():
            nonlocal box_index

            while True:
                try:
                    message = sock.recv(BUFFER_SIZE)
                    while "<EOF>".encode() not in message:
                        message += sock.recv(BUFFER_SIZE)
                    message = message[:-5]

                    with open(f"{KEY_DIRECTORY}/{PRIAVTE_KEY}", "r") as f:
                        terms = f.read().split('\n')

                    d = int(terms[2], 16)
                    n = int(terms[3], 16)

                    message = message.split("<C>".encode())
                    decrypted_message = decrypt(message, d, n)

                    box.insert(box_index, f"{rusername}: {decrypted_message.decode()}")
                    box_index += 1

                except:
                    # messagebox.showerror("Error", "Unable to read message..")
                    break
            messagebox.showerror("Error", "An error occured during communication..\nClosing Connection..")
            
            try:
                app.destroy()
            except:
                pass

        def send_message():
            nonlocal box_index
            message = message_entry.get("1.0",'end-1c')
            message_entry.delete("1.0", "end")
            box.insert(box_index, f"Me: {message}")
            box_index += 1

            with open(f"{KEY_DIRECTORY}/{PUBLIC_KEY}{rusername}", "r") as f:
                terms = f.read().split('\n')
            e = int(terms[0], 16)
            n = int(terms[1], 16)

            encrypted_message = encrypt(message.encode(), e, n)
            encrypted_message_in_bytes = bytes()
            for enc in encrypted_message:
                encrypted_message_in_bytes += enc + "<C>".encode()

            encrypted_message_in_bytes = encrypted_message_in_bytes[:-3] + "<EOF>".encode()

            sock.send(encrypted_message_in_bytes)

        if not fetch_key():
            return

        start_new_thread(receive_messages, ())

        app = Tk()
        app.title("Chat")
        app.geometry('400x500')
        app.resizable(False, False)

        box = Listbox(app, width=66, height=25)
        box.grid(row=0, column=0, columnspan=6, sticky='w', pady=5)

        message_entry = Text(app, width=38, height=4,)
        message_entry.grid(row=1, column=0, columnspan=1, sticky='w', padx=5)

        send_button = Button(app, text="Send", bg="#072D57", fg="white", font=('Verdana', 10,'normal','underline'), height=4, width=8, command=send_message)
        send_button.grid(row=1, column=5, sticky='w')

        app.protocol("WM_DELETE_WINDOW", on_closing)
        app.mainloop()

    def menu_gui(self):
        server_socket = None

        def fetch_address(rusername: str) -> bool:
            with open(f"{KEY_DIRECTORY}/{PRIAVTE_KEY}", 'r') as f:
                terms = f.read().split('\n')

            username = terms[0]
            password = terms[1]

            ttp = TTPClient()

            if not ttp.connect():
                messagebox.showerror("Error", "Unable to connect to the server!")
                return False

            key = ttp.handshake()
            cipher = Fernet(key)

            content = f"username={username}&password={password}&rusername={rusername}"
            encrypted_content = cipher.encrypt(content.encode())

            terms = []
            terms.append(GET + " " + ADDRESS + CRLF)
            terms.append(CONTENT_LENGTH + str(len(encrypted_content)) + CRLF)
            terms.append(CRLF)
            terms.append(encrypted_content)

            ttp.send(terms)
            terms, data_messege = ttp.receive()

            if terms == None:
                messagebox.showerror("Error", "Unable to receive any response from server!")
                return False

            elif terms[0].find(f"200 {OK}") != -1:
                data_messege = cipher.decrypt(data_messege)
                data_messege = data_messege.decode()

                parameters = data_messege.split('&')
                _ip = parameters[0][3:]
                _port = parameters[1][5:]

                with open(f"{KEY_DIRECTORY}/{ADDRESS_FILE}{rusername}", 'w') as f:
                    f.write(f"{_ip}\n{_port}")

                # messagebox.showinfo("Success", f"Address of User: {rusername} fetched Successfully")

            elif terms[0].find(f"403 {BAD_REQUEST}") != -1:
                messagebox.showerror("Error", f"{rusername} doesn't have any server up!")
                return False

            elif terms[0].find(f"401 {BAD_REQUEST}") != -1:
                messagebox.showerror("Error", f"Unable to find {rusername}!")
                return False

            else:
                messagebox.showerror("Error", "An unknown error occured!")
                return False
            
            ttp.close()

            return True

        def execute_client(ip: str, port: int) -> socket:
            try:
                sock = socket(AF_INET, SOCK_STREAM)
                sock.connect((ip, port))
                return sock
            except:
                return None

        def handle_connect():
            if connect_entry.get().strip() == '' or connect_entry.get().find("&") != -1:
                messagebox.showerror("Error", "Please Enter a valid host to connect to!")
                return
            
            rusername = connect_entry.get()
            if not fetch_address(rusername):
                return
            
            with open(f"{KEY_DIRECTORY}/{ADDRESS_FILE}{rusername}", "r") as f:
                terms = f.read().split('\n')

            ip = terms[0]
            port = int(terms[1])

            sock = execute_client(ip, port)
            if sock == None:
                messagebox.showerror("Error", "Unable to connect..")
            else:
                with open(f"{KEY_DIRECTORY}/{PRIAVTE_KEY}", "r") as f:
                    username = f.read().split('\n')[0]

                sock.send(f"{username}<EOF>".encode())
                
                # start_new_thread(self.chatbox, (sock, rusername))
                Process(target=self.chatbox, args=(sock, rusername)).start()

        def process_request(client_socket: socket, client_address: tuple):
            username = client_socket.recv(BUFFER_SIZE)
            while "<EOF>".encode() not in username:
                username += client_socket.recv(BUFFER_SIZE)

            username = username.decode()[:-5]

            if messagebox.askyesno("Connection Request", f"Request From {username} {client_address[0]}:{client_address[1]}"):
                # start_new_thread(self.chatbox, (client_socket, username))
                Process(target=self.chatbox, args=(client_socket, username)).start()
            else:
                client_socket.close()
 
        def execute_server(port: int):
            nonlocal server_socket

            server_socket = socket(AF_INET, SOCK_STREAM)
            
            try:
                server_socket.bind(('', port))
                server_socket.listen(MAX_ALLOWED_CONNECTIONS)
            except:
                messagebox.showerror("Error", f"Unable to bind {port} to socket!")
                return
            
            with open(f"{KEY_DIRECTORY}/{PRIAVTE_KEY}", 'r') as f:
                terms = f.read().split('\n')

            username = terms[0]
            password = terms[1]
            
            ttp = TTPClient()

            if not ttp.connect():
                messagebox.showerror("Error", "Unable to connect to the server!")
                return

            key = ttp.handshake()
            cipher = Fernet(key)

            content = f"username={username}&password={password}&port={port}"
            encrypted_content = cipher.encrypt(content.encode())

            terms = []
            terms.append(SET + CRLF)
            terms.append(CONTENT_LENGTH + str(len(encrypted_content)) + CRLF)
            terms.append(CRLF)
            terms.append(encrypted_content)

            ttp.send(terms)
            terms, data_messege = ttp.receive()

            if terms == None:
                messagebox.showerror("Error", "Unable to receive any response from server!")
                return

            elif terms[0].find(f"200 {OK}") != -1:
                # messagebox.showinfo("Success", "IP address and port updated Successfully")
                pass

            else:
                messagebox.showerror("Error", "An unknown error occured!")
                return

            ttp.close()

            # start_button['text'] = 'Stop'
            start_button['text'] = 'Started'
            start_button['state'] = 'disabled'
            port_entry['state'] = 'disabled'

            executor = ThreadPoolExecutor(max_workers=MAX_ALLOWED_CONNECTIONS)
            while True:
                try:
                    client_socket, client_address = server_socket.accept()
                    executor.submit(process_request, client_socket, client_address)
                except:
                    break
            
            try:
                server_socket.shutdown(SHUT_RDWR)
                server_socket.close()
            except:
                pass
            server_socket = None
            start_button['text'] = 'Start'
            
        def handle_start():
            if start_button['text'] == 'Start':
                try:
                    port = int(port_entry.get())
                except:
                    messagebox.showerror("Error", "Please Enter a valid port!")
                    return

                if port < 1024 or port > 65535:
                    messagebox.showerror("Error", "Please Enter a valid port!")
                    return

                start_new_thread(execute_server, (port, ))

            elif start_button['text'] == 'Stop':
                try:
                    server_socket.shutdown(SHUT_RDWR)
                    server_socket.close()
                except:
                    pass
                server_socket = None
                start_button['text'] = 'Start'
                
        def handle_generation_and_revocation(operation: str):
            with open(f"{KEY_DIRECTORY}/{PRIAVTE_KEY}", 'r') as f:
                terms = f.read().split('\n')

            username = terms[0]
            password = terms[1]

            ttp = TTPClient()

            if not ttp.connect():
                messagebox.showerror("Error", "Unable to connect to the server!")
                return

            key = ttp.handshake()
            cipher = Fernet(key)
            
            content = f"username={username}&password={password}"
            encrypted_content = cipher.encrypt(content.encode())

            terms = []
            terms.append(operation + CRLF)
            terms.append(CONTENT_LENGTH + str(len(encrypted_content)) + CRLF)
            terms.append(CRLF)
            terms.append(encrypted_content)

            ttp.send(terms)
            terms, data_messege = ttp.receive()

            if terms == None:
                messagebox.showerror("Error", "Unable to receive any response from server!")
                return

            elif terms[0].find(f"200 {OK}") != -1:
                data_messege = cipher.decrypt(data_messege)
                data_messege = data_messege.decode()

                priv_key = data_messege.split('&')
                d = priv_key[0][2:]
                n = priv_key[1][2:]

                with open(f"{KEY_DIRECTORY}/{PRIAVTE_KEY}", 'w') as f:
                    f.write(f"{username}\n{password}\n{d}\n{n}")

                messagebox.showinfo("Success", f"Key {operation} Successfully")

            else:
                messagebox.showerror("Error", "An unknown error occured!")

            ttp.close()

        app = Tk()
        app.title("Menu")
        app.geometry('425x310')
        app.resizable(False, False)

        C = Canvas(app, height=225, width=375)
        C.pack(fill='both', expand=True)
        bg = ImageTk.PhotoImage(Image.open(LOGO_PATH).resize((125,75)))
        C.create_image(150, 25, image=bg, anchor="nw")

        serverFrame = LabelFrame(app, text="Server", width=325, height=50)
        C.create_window(50, 110, window=serverFrame, anchor="nw")

        Label(serverFrame, text="Port             ").grid(row=1, column=1)

        port_entry = Entry(serverFrame, width=30)
        port_entry.grid(row=1, column=2)

        start_button = Button(serverFrame, text="Start", width=7, command=handle_start)
        start_button.grid(row=1, column=3, padx=5, pady=2)

        clientFrame = LabelFrame(app, text="Client", width=325, height=50)
        C.create_window(50, 180, window=clientFrame, anchor="nw")

        Label(clientFrame, text="Connect to ").grid(row=1, column=1)

        connect_entry = Entry(clientFrame, width=30)
        connect_entry.grid(row=1, column=2)

        Button(clientFrame, text="Connect", width=7, command=handle_connect).grid(row=1, column=3, padx=5, pady=2)

        generate_button = Button(app, text="Generate Key", width=10, borderwidth=2, bg="#072D57", fg="white", command=lambda: handle_generation_and_revocation(GENERATE))
        C.create_window(130, 250, window=generate_button, anchor="nw")

        revocate_button = Button(app, text="Revocate Key", width=10, borderwidth=2, bg="#072D57", fg="white", command=lambda: handle_generation_and_revocation(REVOCATE))
        C.create_window(220, 250, window=revocate_button, anchor="nw")

        app.mainloop()

    def register_gui(self):
        def handle_register():
            if user_entry.get().strip() == '' or password_entry.get() == '':
                messagebox.showerror("Error", "Either username or password Entry is Empty!")
                return

            if not user_entry.get().isalnum():
                messagebox.showerror("Error", "username can contain numbers and letters only!")
                return

            ttp = TTPClient()
            if not ttp.connect():
                messagebox.showerror("Error", "Unable to connect to the server!")
                return

            key = ttp.handshake()
            cipher = Fernet(key)

            hashed_password = getHash(password_entry.get())
            content = f"username={user_entry.get()}&password={hashed_password}"
            encrypted_content = cipher.encrypt(content.encode())

            terms = []
            terms.append(REGISTER + CRLF)
            terms.append(CONTENT_LENGTH + str(len(encrypted_content)) + CRLF)
            terms.append(CRLF)
            terms.append(encrypted_content)

            ttp.send(terms)
            terms, data_messege = ttp.receive()

            if terms == None:
                messagebox.showerror("Error", "Unable to receive any response from server!")
                return
                
            elif terms[0].find(f"200 {OK}") != -1:
                data_messege = cipher.decrypt(data_messege)
                data_messege = data_messege.decode()
                priv_key = data_messege.split('&')
                d = priv_key[0][2:]
                n = priv_key[1][2:]

                with open(f"{KEY_DIRECTORY}/{PRIAVTE_KEY}", 'w') as f:
                    f.write(f"{user_entry.get()}\n{hashed_password}\n{d}\n{n}")

                app.destroy()
                self.menu_gui()

            elif terms[0].find(f"402 {BAD_REQUEST}") != -1:
                messagebox.showerror("Error", "Username already exists!")
            
            else:
                messagebox.showerror("Error", "An error occured while communticating with server!")

            ttp.close()

        def handle_login_link():
            app.destroy()
            self.login_gui()

        app = Tk()
        app.title("Register")
        app.geometry('425x250')
        app.resizable(False, False)

        C = Canvas(app, height=225, width=375)
        C.pack(fill='both', expand=True)
        bg = ImageTk.PhotoImage(Image.open(LOGO_PATH).resize((125,75)))
        C.create_image(150, 25, image=bg, anchor="nw")

        C.create_text(100, 150, text="Username", fill='black')
        C.create_text(100, 180, text="Password", fill='black')

        user_entry = Entry(app, width=30)
        password_entry = Entry(app, width=30, show='*')
                            
        C.create_window(140, 140, window=user_entry, anchor="nw")
        C.create_window(140, 170, window=password_entry, anchor="nw")

        submit_button = Button(app, text="Register", width=10, borderwidth=1, bg="#072D57", fg="white", command=handle_register)
        C.create_window(177, 200, window=submit_button, anchor="nw")

        link_button = Button(app, text="Login", width=10, borderwidth=0, fg="blue", font=('Verdana', 9,'normal','underline'), command=handle_login_link)
        C.create_window(340, 220, window=link_button, anchor="nw")

        app.mainloop()

    def login_gui(self):
        def handle_login():
            if user_entry.get().strip() == '' or password_entry.get() == '':
                messagebox.showerror("Error", "Either username or password Entry is Empty!")
                return

            if not user_entry.get().isalnum():
                messagebox.showerror("Error", "username can contain numbers and letters only!")
                return

            ttp = TTPClient()
            if not ttp.connect():
                messagebox.showerror("Error", "Unable to connect to the server!")
                return

            key = ttp.handshake()
            cipher = Fernet(key)

            hashed_password = getHash(password_entry.get())
            content = f"username={user_entry.get()}&password={hashed_password}"
            encrypted_content = cipher.encrypt(content.encode())

            terms = []
            terms.append(LOGIN + CRLF)
            terms.append(CONTENT_LENGTH + str(len(content)) + CRLF)
            terms.append(CRLF)
            terms.append(encrypted_content)

            ttp.send(terms)
            terms, data_messege = ttp.receive()

            if terms == None:
                messagebox.showerror("Error", "Unable to receive any response from server!")
                return
                
            elif terms[0].find(f"200 {OK}") != -1:
                data_messege = cipher.decrypt(data_messege)
                data_messege = data_messege.decode()
                priv_key = data_messege.split('&')
                d = priv_key[0][2:]
                n = priv_key[1][2:]

                with open(f"{KEY_DIRECTORY}/{PRIAVTE_KEY}", 'w') as f:
                    f.write(f"{user_entry.get()}\n{hashed_password}\n{d}\n{n}")

                app.destroy()
                self.menu_gui()

            elif terms[0].find(f"402 {BAD_REQUEST}") != -1:
                messagebox.showerror("Error", "Invalid Password!")

            elif terms[0].find(f"404 {BAD_REQUEST}") != -1:
                messagebox.showerror("Error", "Unable to find Username!")
            
            else:
                messagebox.showerror("Error", "An error occured while communticating with server!")

            ttp.close()

        def handle_register_link():
            app.destroy()
            self.register_gui()

        app = Tk()
        app.title("Login")
        app.geometry('425x250')
        app.resizable(False, False)

        C = Canvas(app, height=225, width=375)
        C.pack(fill='both', expand=True)
        bg = ImageTk.PhotoImage(Image.open(LOGO_PATH).resize((125,75)))
        C.create_image(150, 25, image=bg, anchor="nw")

        C.create_text(100, 150, text="Username", fill='black')
        C.create_text(100, 180, text="Password", fill='black')

        user_entry = Entry(app, width=30)
        password_entry = Entry(app, width=30, show='*')
                            
        C.create_window(140, 140, window=user_entry, anchor="nw")
        C.create_window(140, 170, window=password_entry, anchor="nw")

        submit_button = Button(app, text="Login", width=10, borderwidth=1, bg="#072D57", fg="white", command=handle_login)
        C.create_window(177, 200, window=submit_button, anchor="nw")

        link_button = Button(app, text="Register", width=10, borderwidth=0, fg="blue", font=('Verdana', 9,'normal','underline'), command=handle_register_link)
        C.create_window(340, 220, window=link_button, anchor="nw")

        app.mainloop()

if __name__ == "__main__":
    app = App()
    app.login_gui()