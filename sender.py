import os
from tkinter import filedialog, messagebox, Button, Frame, Tk, Label, Text, Entry

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

public_key_A = None

sender_root = Tk()
sender_root.title("User A - RSA Encryption")

frame_sender = Frame(sender_root)
frame_sender.pack(pady=20)

Label(frame_sender, text="User A's RSA Encryption", font=("Arial", 16)).grid(row=0, columnspan=2, pady=10)

def generate_key_pair():
    global private_key_A, public_key_A
    
    messagebox.showinfo("Key Generation", "Creating Private Key...")
    
    try:
        private_key_A = RSA.generate(2048)
        public_key_A = private_key_A.publickey()

        private_key_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
        if private_key_path:
            with open(private_key_path, 'wb') as private_file:
                private_file.write(private_key_A.export_key())
        
        messagebox.showinfo("Key Generation", "Private Key Created and Saved!")

        messagebox.showinfo("Key Generation", "Creating Public Key...")

        public_key_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
        if public_key_path:
            with open(public_key_path, 'wb') as public_file:
                public_file.write(public_key_A.export_key())
        
        # Show dialog box after creating the public key
        messagebox.showinfo("Key Generation", "Public Key Created and Saved!")

    except Exception as e:
        messagebox.showerror("Key Generation Error", f"Error generating key pair: {str(e)}")

# Function to load User B's public key and encrypt the message (used by User A)
def load_public_key_and_encrypt_message():
    global public_key_A
    # Open file dialog to select the public key of User B
    file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
    if file_path:
        try:
            with open(file_path, 'rb') as file:
                public_key_A = RSA.import_key(file.read())

            # Get the message from the text entry widget
            message = entry_message.get()  # Get the text entered in the Entry widget
            
            if not message:  # Check if the message is empty
                messagebox.showerror("Input Error", "Please enter a message to encrypt.")
                return
            
            # Encrypt the message using the public key of User B
            cipher_rsa = PKCS1_OAEP.new(public_key_A)
            encrypted_message = cipher_rsa.encrypt(message.encode())

            # Save the encrypted message to a file
            encrypted_message_path = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("Binary files", "*.bin")])
            if encrypted_message_path:
                with open(encrypted_message_path, 'wb') as file:
                    file.write(encrypted_message)

            messagebox.showinfo("Message", "Message encrypted successfully and saved.")
        except Exception as e:
            messagebox.showerror("Encryption Error", f"Error encrypting the message: {str(e)}")
    else:
        messagebox.showerror("Load Error", "Failed to load public key.")

# Add a text entry field for the user to input the message
Label(frame_sender, text="Enter message to encrypt:").grid(row=1, column=0, pady=10)
entry_message = Entry(frame_sender, width=50)
entry_message.grid(row=1, column=1, pady=10)

# Buttons for User A to generate key pair, load public key, and encrypt message
Button(frame_sender, text="Generate Key Pair", command=generate_key_pair, width=20).grid(row=2, column=0, pady=5)
Button(frame_sender, text="Load Public Key and Encrypt Message", command=load_public_key_and_encrypt_message, width=20).grid(row=2, column=1, pady=5)

# Start the sender (User A) GUI event loop
sender_root.mainloop()
