import os
from tkinter import filedialog, messagebox, Text, Tk, Button, Label, Frame
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Global variables for private key and encryption/decryption status
private_key_A = None
is_private_key_loaded = False  # Flag to track if private key is loaded

# Receiver (User B) GUI
receiver_root = Tk()
receiver_root.title("User B - RSA Decryption")

# Frame for receiver's operations
frame_receiver = Frame(receiver_root)
frame_receiver.pack(pady=20)

# Title Label for Receiver (User B)
Label(frame_receiver, text="User B's RSA Decryption", font=("Arial", 16)).grid(row=0, columnspan=2, pady=10)

# Function to load the private key (used by User B)
def load_private_key():
    global private_key_A, is_private_key_loaded
    file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
    if file_path:
        try:
            with open(file_path, 'rb') as file:
                private_key_A = RSA.import_key(file.read())
            is_private_key_loaded = True  # Mark the private key as loaded
            messagebox.showinfo("Load Key", "Private key loaded successfully.")
        except Exception as e:
            messagebox.showerror("Load Error", f"Error loading private key: {str(e)}")
    else:
        messagebox.showerror("Load Error", "Failed to load private key.")

# Function to load and decrypt the message (used by User B)
def load_and_decrypt_message():
    global private_key_A, is_private_key_loaded
    if not is_private_key_loaded:
        messagebox.showerror("Decryption Error", "Please load your private key first.")
        return  # Exit if private key is not loaded

    # Open file dialog to select encrypted message
    file_path = filedialog.askopenfilename(filetypes=[("Binary files", "*.bin")])
    if file_path:
        try:
            with open(file_path, 'rb') as file:
                encrypted_message = file.read()

            # Proceed with decryption using the loaded private key
            if private_key_A:
                cipher_rsa = PKCS1_OAEP.new(private_key_A)
                decrypted_message = cipher_rsa.decrypt(encrypted_message)
                # Display the decrypted message in the text widget
                text_decrypted_message.delete("1.0", "end")  # Clear previous message
                text_decrypted_message.insert("1.0", decrypted_message.decode())  # Insert new decrypted message
                messagebox.showinfo("Decryption", "Message decrypted successfully.")
        except (ValueError, TypeError) as e:
            messagebox.showerror("Decryption Error", f"Failed to decrypt the message: {str(e)}")
        except Exception as e:
            messagebox.showerror("File Error", f"Error reading encrypted message: {str(e)}")

# Create a text widget to display the decrypted message
text_decrypted_message = Text(frame_receiver, height=10, width=50)
text_decrypted_message.grid(row=2, columnspan=2, pady=10)

# Buttons for User B to load private key and decrypt message
Button(frame_receiver, text="Load Private Key", command=load_private_key, width=20).grid(row=1, column=0, pady=5)
Button(frame_receiver, text="Load and Decrypt Message", command=load_and_decrypt_message, width=20).grid(row=1, column=1, pady=5)

# Start the receiver (User B) GUI event loop
receiver_root.mainloop()
