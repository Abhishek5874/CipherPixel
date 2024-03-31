import cv2
import os
import tkinter as tk
from tkinter import ttk, messagebox, Toplevel
import hashlib

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption App")

        self.secret_message_var = tk.StringVar()
        self.password_var = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self.root, text="Enter secret message:").pack(pady=5)
        secret_message_entry = ttk.Entry(self.root, textvariable=self.secret_message_var)
        secret_message_entry.pack(pady=5)

        ttk.Label(self.root, text="Enter password:").pack(pady=5)
        password_entry = ttk.Entry(self.root, textvariable=self.password_var, show="*")
        password_entry.pack(pady=5)

        encrypt_button = ttk.Button(self.root, text="Encrypt", command=self.encrypt_message)
        encrypt_button.pack(pady=10)

        decrypt_button = ttk.Button(self.root, text="Decrypt", command=self.open_decryption_window)
        decrypt_button.pack(pady=10)

    def encrypt_message(self):
        end_marker = "~"
        secret_message = self.secret_message_var.get()
        password = self.password_var.get()

        if not secret_message:
            messagebox.showwarning("Warning", "Please enter a secret message.")
            return

        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return

        encrypted_msg = self.encrypt_message_func(secret_message, end_marker, password)
        cv2.imwrite("Encryptedmsg.png", encrypted_msg)
        os.system("start Encryptedmsg.png")

    def encrypt_message_func(self, message, end_marker, password):
        img = cv2.imread("mypic.jpg", cv2.IMREAD_UNCHANGED)
        m, n, z = 0, 0, 0

        for char in message:
            if char == end_marker:
                break
            img[n, m, z] = ord(char)
            n, m, z = n + 1, m + 1, (z + 1) % 3

        password_hash = self.hash_password(password)
        img[-1, -1, -1] = password_hash

        return img

    def open_decryption_window(self):
        end_marker = "~"
        password = self.password_var.get()

        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return

        encrypted_msg = cv2.imread("Encryptedmsg.png", cv2.IMREAD_UNCHANGED)
        decrypted_msg = self.decrypt_message(encrypted_msg, end_marker, password)

        if not decrypted_msg:
            messagebox.showerror("Error", "Invalid password! Decryption failed.")
            return

        self.show_decrypted_message(decrypted_msg)

    def decrypt_message(self, img, end_marker, password):
        stored_password_hash = img[-1, -1, -1]
        if self.hash_password(password) != stored_password_hash:
            messagebox.showerror("Error", "Invalid password! Decryption failed.")
            return ""

        message = ""
        n, m, z = 0, 0, 0

        while True:
            char = chr(img[n, m, z])
            if char == end_marker:
                break
            message += char
            n, m, z = n + 1, m + 1, (z + 1) % 3

        return message.strip()  # Use strip to remove leading and trailing whitespaces

    def show_decrypted_message(self, decrypted_msg):
        decryption_window = Toplevel(self.root)
        decryption_window.title("Decrypted Message")

        ttk.Label(decryption_window, text="Decrypted Message:").pack(pady=5)
        ttk.Label(decryption_window, text=decrypted_msg).pack(pady=10)

    def hash_password(self, password):
        sha256 = hashlib.sha256(password.encode()).hexdigest()
        return int(sha256, 16) % 256

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
