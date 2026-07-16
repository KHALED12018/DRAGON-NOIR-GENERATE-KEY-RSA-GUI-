import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes
import binascii

class AdvancedKeyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DRAGON_NOIR GENERATE KEY RSA GUI")
        self.root.geometry("1100x800")
        self.root.configure(bg="#1a252f")
        
        self.key_obj = None
        self.pkcs_standard = tk.StringVar(value="PKCS#1 v1.5")
        
        self.create_widgets()

    def create_widgets(self):
        title_label = tk.Label(
            self.root, text="DRAGON_NOIR GENERATE KEY RSA GUI", 
            font=("Arial", 18, "bold"), bg="#1a252f", fg="#ecf0f1"
        )
        title_label.pack(pady=15)

        control_frame = tk.LabelFrame(
            self.root, text=" CONTROLS ", font=("Arial", 10, "bold"),
            bg="#1a252f", fg="#ecf0f1", bd=3, relief=tk.GROOVE
        )
        control_frame.pack(pady=10, fill=tk.X, padx=20, ipady=5)

        combo_label = tk.Label(
            control_frame, text="Key Standard:", 
            font=("Arial", 10, "bold"), bg="#1a252f", fg="#ecf0f1"
        )
        combo_label.pack(side=tk.RIGHT, padx=5)

        self.standard_combo = ttk.Combobox(
            control_frame, textvariable=self.pkcs_standard, 
            values=["PKCS#1 v1.5", "PKCS#8"], state="readonly", width=15, font=("Arial", 10, "bold")
        )
        self.standard_combo.pack(side=tk.RIGHT, padx=10)

        self.gen_btn = tk.Button(
            control_frame, text="Generate RSA Keys", command=self.generate_keys,
            font=("Arial", 10, "bold"), bg="#27ae60", fg="white",
            relief=tk.RAISED, bd=4, cursor="hand2", padx=10, pady=4
        )
        self.gen_btn.pack(side=tk.RIGHT, padx=5)

        self.import_btn = tk.Button(
            control_frame, text="Import Key File...", command=self.import_key_file,
            font=("Arial", 10, "bold"), bg="#e67e22", fg="white",
            relief=tk.RAISED, bd=4, cursor="hand2", padx=10, pady=4
        )
        self.import_btn.pack(side=tk.RIGHT, padx=5)

        self.save_priv_btn = tk.Button(
            control_frame, text="Save Private Key...", command=self.save_private_key,
            font=("Arial", 10, "bold"), bg="#2980b9", fg="white",
            relief=tk.RAISED, bd=4, cursor="hand2", padx=10, pady=4, state=tk.DISABLED
        )
        self.save_priv_btn.pack(side=tk.LEFT, padx=5)

        self.save_pub_btn = tk.Button(
            control_frame, text="Save Public Key...", command=self.save_public_key,
            font=("Arial", 10, "bold"), bg="#8e44ad", fg="white",
            relief=tk.RAISED, bd=4, cursor="hand2", padx=10, pady=4, state=tk.DISABLED
        )
        self.save_pub_btn.pack(side=tk.LEFT, padx=5)

        display_frame = tk.Frame(self.root, bg="#1a252f")
        display_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=10)

        priv_frame = tk.LabelFrame(
            display_frame, text=" PRIVATE KEY HEX COMPONENTS (n, d, p, q) ", 
            font=("Arial", 10, "bold"), bg="#2c3e50", fg="#1abc9c", bd=3, relief=tk.GROOVE
        )
        priv_frame.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH, padx=5, pady=5)

        self.priv_text = tk.Text(
            priv_frame, wrap=tk.WORD, bg="#0d1117", fg="#58a6ff", 
            font=("Courier New", 9), relief=tk.SUNKEN, bd=5
        )
        self.priv_text.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)

        pub_frame = tk.LabelFrame(
            display_frame, text=" PUBLIC / CERT HEX COMPONENTS (n, e) ", 
            font=("Arial", 10, "bold"), bg="#2c3e50", fg="#1abc9c", bd=3, relief=tk.GROOVE
        )
        pub_frame.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=5, pady=5)

        self.pub_text = tk.Text(
            pub_frame, wrap=tk.WORD, bg="#0d1117", fg="#58a6ff", 
            font=("Courier New", 9), relief=tk.SUNKEN, bd=5
        )
        self.pub_text.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)
        
        self.status = tk.Label(
            self.root, text="Ready...", bd=2, 
            relief=tk.SUNKEN, anchor=tk.W, bg="#2c3e50", fg="#bdc3c7"
        )
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

    def to_clean_hex_space(self, val, target_bytes=None):
        if target_bytes:
            try:
                val_bytes = val.to_bytes(target_bytes, byteorder='big')
            except OverflowError:
                val_bytes = long_to_bytes(val)
        else:
            val_bytes = long_to_bytes(val)
            
        hex_str = val_bytes.hex()
        cleaned_hex = hex_str.rstrip('0')
        if len(cleaned_hex) % 2 != 0:
            cleaned_hex += '0'
            
        spaced_hex = " ".join(cleaned_hex[i:i+2] for i in range(0, len(cleaned_hex), 2))
        return "00 08 00 00 " + spaced_hex

    def parse_and_display(self):
        if not self.key_obj:
            return
        
        n_val = self.key_obj.n
        e_val = self.key_obj.e
        
        n_hex = self.to_clean_hex_space(n_val)
        e_hex = self.to_clean_hex_space(e_val)
        
        if self.key_obj.has_private():
            d_val = self.key_obj.d
            p_val = self.key_obj.p
            q_val = self.key_obj.q
            
            d_hex = self.to_clean_hex_space(d_val)
            p_hex = self.to_clean_hex_space(p_val)
            q_hex = self.to_clean_hex_space(q_val)
            
            priv_display = (
                f"--- PRIVATE KEY COMPONENTS ---\n"
                f"Selected Standard: {self.pkcs_standard.get()}\n\n"
                f"[Modulus (n) Hex without padding]:\n{n_hex}\n\n"
                f"[Private Exponent (d) Hex]:\n{d_hex}\n\n"
                f"[Prime p Hex]:\n{p_hex}\n\n"
                f"[Prime q Hex]:\n{q_hex}\n"
            )
            self.save_priv_btn.config(state=tk.NORMAL)
        else:
            priv_display = "--- PUBLIC KEY LOADED ---\n\n(No Private Key components available in this file)"
            self.save_priv_btn.config(state=tk.DISABLED)
            
        pub_display = (
            f"--- PUBLIC KEY / CERT COMPONENTS ---\n\n"
            f"[Modulus (n) Hex without padding]:\n{n_hex}\n\n"
            f"[Public Exponent (e) Hex]:\n{e_hex}\n"
        )
        
        self.priv_text.delete("1.0", tk.END)
        self.priv_text.insert(tk.END, priv_display)
        
        self.pub_text.delete("1.0", tk.END)
        self.pub_text.insert(tk.END, pub_display)
        
        self.save_pub_btn.config(state=tk.NORMAL)

    def generate_keys(self):
        try:
            self.status.config(text="Generating RSA 2048-bit key...")
            self.root.update()
            self.key_obj = RSA.generate(2048)
            self.parse_and_display()
            self.status.config(text="Key generated and hex components extracted successfully.")
            messagebox.showinfo("Success", "Keys generated.")
        except Exception as e:
            messagebox.showerror("Error", f"Error during generation: {str(e)}")

    def import_key_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Key File to Import",
            filetypes=[
                ("All Supported Keys", "*.pem *.der *.bin *.key *.crt *.pub"),
                ("PEM / DER Files", "*.pem *.der"),
                ("Binary / Raw Files", "*.bin *.key"),
                ("All Files", "*.*")
            ]
        )
        if not file_path:
            return
            
        try:
            self.status.config(text="Reading key file...")
            self.root.update()
            
            with open(file_path, "rb") as f:
                key_data = f.read()
                
            try:
                self.key_obj = RSA.import_key(key_data)
            except Exception:
                try:
                    cleaned_data = key_data.replace(b'\r', b'').replace(b'\n', b'')
                    hex_data = binascii.unhexlify(cleaned_data)
                    self.key_obj = RSA.import_key(hex_data)
                except Exception:
                    raise ValueError("Check key file format.")

            self.parse_and_display()
            self.status.config(text=f"Key imported successfully from: {file_path}")
            messagebox.showinfo("Success", "Key imported.")
        except Exception as e:
            messagebox.showerror("Error", f"Import failed: {str(e)}")

    def save_private_key(self):
        if not self.key_obj or not self.key_obj.has_private():
            return
        
        file_types = [
            ("PEM Private Key (*.pem)", "*.pem"),
            ("DER Binary Private Key (*.der)", "*.der"),
            ("Binary Key File (*.bin)", "*.bin"),
            ("PKCS12 Bundle (*.pfx)", "*.pfx"),
            ("PKCS12 Bundle (*.pks)", "*.pks"),
            ("All Files (*.*)", "*.*")
        ]
        
        file_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=file_types, title="Save Private Key")
        if file_path:
            try:
                selected_standard = self.pkcs_standard.get()
                pkcs_val = 1 if selected_standard == "PKCS#1 v1.5" else 8
                
                if file_path.endswith('.der') or file_path.endswith('.bin'):
                    data = self.key_obj.export_key(format='DER', pkcs=pkcs_val)
                elif file_path.endswith('.pfx') or file_path.endswith('.pks'):
                    data = self.key_obj.export_key(format='PEM', pkcs=pkcs_val, passphrase='password123', protection='PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC')
                    messagebox.showinfo("Notice", "PFX saved with default password: password123")
                else:
                    data = self.key_obj.export_key(format='PEM', pkcs=pkcs_val)
                
                with open(file_path, 'wb') as f:
                    f.write(data)
                self.status.config(text=f"Private key saved to: {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Save failed: {str(e)}")

    def save_public_key(self):
        if not self.key_obj:
            return
        
        file_types = [
            ("PEM Public Key (*.pem)", "*.pem"),
            ("DER Public Key (*.der)", "*.der"),
            ("Binary Key File (*.bin)", "*.bin"),
            ("Certificate File (*.crt)", "*.crt"),
            ("Certificate File (*.cert)", "*.cert"),
            ("All Files (*.*)", "*.*")
        ]
        
        file_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=file_types, title="Save Public Key")
        if file_path:
            try:
                pub_key = self.key_obj.publickey()
                
                if file_path.endswith('.der') or file_path.endswith('.bin'):
                    data = pub_key.export_key(format='DER')
                else:
                    data = pub_key.export_key(format='PEM')
                
                with open(file_path, 'wb') as f:
                    f.write(data)
                self.status.config(text=f"Public key saved to: {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Save failed: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedKeyApp(root)
    root.mainloop()