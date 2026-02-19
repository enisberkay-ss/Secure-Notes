import tkinter as tk
from tkinter import messagebox
import time
import sys
import traceback

from database import DatabaseManager
from auth import AuthManager
from encryption import EncryptionManager


class SecureNotesApp:

    def __init__(self, root):
        self.root = root
        self.root.title("Secure Notes")
        self.root.geometry("800x600")
        
        # Window close protocol
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        try:
            self.db = DatabaseManager()
            self.db.connect()
            self.db.create_tables()
        except Exception as e:
            messagebox.showerror("Database Error", f"Could not connect to database:\n{str(e)}")
            self.root.destroy()
            sys.exit(1)

        self.auth = AuthManager()
        self.encryption_manager = None
        self.frame_stack = []
        self.locked_until = 0

        # Global key bindings
        self.root.bind("<Escape>", self.go_back)
        self.root.bind("<Return>", self.handle_enter)

        # Show welcome screen on startup
        self.show_welcome()

    def on_closing(self):
        """Cleanup when window closes"""
        try:
            if hasattr(self, 'db') and self.db.conn:
                self.db.conn.close()
        except:
            pass
        self.root.destroy()
        sys.exit(0)

    # -----------------------
    # FRAME MANAGEMENT
    # -----------------------
    def show_frame(self, frame_class, *args, **kwargs):
        try:
            # Hide previous frame
            if self.frame_stack:
                self.frame_stack[-1].pack_forget()

            # Create new frame
            if callable(frame_class) and not isinstance(frame_class, type):
                frame = frame_class(self)
            else:
                frame = frame_class(self, *args, **kwargs)
                
            frame.pack(fill="both", expand=True)
            self.frame_stack.append(frame)
        except Exception as e:
            messagebox.showerror("Frame Error", f"Error loading screen:\n{str(e)}")
            traceback.print_exc()

    def go_back(self, event=None):
        try:
            if len(self.frame_stack) > 1:
                current = self.frame_stack.pop()
                current.destroy()
                self.frame_stack[-1].pack(fill="both", expand=True)
        except Exception as e:
            print(f"Go back error: {e}")

    def handle_enter(self, event=None):
        try:
            if self.frame_stack:
                frame = self.frame_stack[-1]
                if hasattr(frame, "primary_action"):
                    frame.primary_action()
        except Exception as e:
            print(f"Enter key error: {e}")

    # -----------------------
    # WELCOME SCREEN
    # -----------------------
    def show_welcome(self):
        self.show_frame(WelcomeFrame)

    # -----------------------
    # LOGIN
    # -----------------------
    def show_login(self):
        self.show_frame(LoginFrame)

    def login_success(self, encryption_manager):
        try:
            self.encryption_manager = encryption_manager
            while self.frame_stack:
                old = self.frame_stack.pop()
                old.destroy()
            self.show_frame(NotesListFrame)
        except Exception as e:
            messagebox.showerror("Error", f"Login successful but could not open main screen:\n{str(e)}")

    # -----------------------
    # REGISTER
    # -----------------------
    def show_register(self):
        self.show_frame(RegisterFrame)

    def register_success(self, encryption_manager):
        try:
            self.encryption_manager = encryption_manager
            while self.frame_stack:
                old = self.frame_stack.pop()
                old.destroy()
            self.show_frame(NotesListFrame)
        except Exception as e:
            messagebox.showerror("Error", f"Registration successful but could not open main screen:\n{str(e)}")


# ===================================================
# WELCOME FRAME
# ===================================================

class WelcomeFrame(tk.Frame):
    def __init__(self, app):
        super().__init__(app.root)
        self.app = app

        tk.Label(self, text=" Secure Notes", font=("Arial", 24, "bold")).pack(pady=50)
        tk.Label(self, text="Welcome", font=("Arial", 16)).pack(pady=10)

        button_frame = tk.Frame(self)
        button_frame.pack(pady=30)

        tk.Button(
            button_frame, 
            text="Login", 
            font=("Arial", 12),
            width=20,
            height=2,
            command=self.go_to_login
        ).pack(pady=10)

        tk.Button(
            button_frame, 
            text="Register", 
            font=("Arial", 12),
            width=20,
            height=2,
            command=self.go_to_register
        ).pack(pady=10)

    def go_to_login(self):
        try:
            user = self.app.db.get_master_user()
            if user is None:
                messagebox.showinfo("Info", "No registered user found.\nPlease use 'Register' to create an account first.")
                return
            self.app.show_login()
        except Exception as e:
            messagebox.showerror("Error", f"Could not open login screen:\n{str(e)}")

    def go_to_register(self):
        try:
            user = self.app.db.get_master_user()
            if user is not None:
                messagebox.showwarning("Warning", "A master password already exists!\nMultiple accounts are not allowed.")
                return
            self.app.show_register()
        except Exception as e:
            messagebox.showerror("Error", f"Could not open registration screen:\n{str(e)}")


# ===================================================
# REGISTER FRAME
# ===================================================

class RegisterFrame(tk.Frame):
    def __init__(self, app):
        super().__init__(app.root)
        self.app = app

        tk.Label(self, text="Create Master Password", font=("Arial", 18, "bold")).pack(pady=30)

        tk.Label(self, text="New Master Password:", font=("Arial", 12)).pack(pady=5)
        self.password_entry = tk.Entry(self, show="*", width=30, font=("Arial", 11))
        self.password_entry.pack()
        self.password_entry.focus()

        tk.Label(self, text="Confirm Master Password:", font=("Arial", 12)).pack(pady=5)
        self.confirm_entry = tk.Entry(self, show="*", width=30, font=("Arial", 11))
        self.confirm_entry.pack()

        self.status = tk.Label(self, text="", fg="red", font=("Arial", 10))
        self.status.pack(pady=10)

        button_frame = tk.Frame(self)
        button_frame.pack(pady=20)

        tk.Button(
            button_frame, 
            text="Create", 
            font=("Arial", 11),
            width=15,
            command=self.primary_action
        ).pack(side="left", padx=5)

        tk.Button(
            button_frame, 
            text="Back", 
            font=("Arial", 11),
            width=15,
            command=self.app.go_back
        ).pack(side="left", padx=5)

    def primary_action(self):
        try:
            password = self.password_entry.get()
            confirm = self.confirm_entry.get()

            if not password:
                self.status.config(text=" Password cannot be empty!", fg="red")
                return

            if len(password) < 8:
                self.status.config(text=" Password must be at least 8 characters!", fg="red")
                return

            if password != confirm:
                self.status.config(text=" Passwords do not match!", fg="red")
                return

            # Create master password
            salt = self.app.auth.generate_salt()
            key_hash, salt_hex = self.app.auth.create_master_password(password)
            
            # Save to database
            self.app.db.cursor.execute("""
                INSERT INTO master_user (id, password_hash, salt)
                VALUES (1, ?, ?)
            """, (key_hash, salt_hex))
            self.app.db.conn.commit()

            # Create encryption manager
            salt_bytes = bytes.fromhex(salt_hex)
            root_key = self.app.auth.derive_root_key(password, salt_bytes)
            encryption_key = self.app.auth.derive_subkey(root_key, "encryption")
            enc_manager = EncryptionManager(encryption_key)

            messagebox.showinfo("Success", " Master password created successfully!\n\nWelcome to Secure Notes.")
            self.app.register_success(enc_manager)

        except Exception as e:
            self.status.config(text=f" Error: {str(e)}", fg="red")
            traceback.print_exc()


# ===================================================
# LOGIN FRAME
# ===================================================

class LoginFrame(tk.Frame):
    def __init__(self, app):
        super().__init__(app.root)
        self.app = app

        tk.Label(self, text="Master Password Login", font=("Arial", 18, "bold")).pack(pady=30)

        self.password_entry = tk.Entry(self, show="*", width=30, font=("Arial", 11))
        self.password_entry.pack()
        self.password_entry.focus()

        self.status = tk.Label(self, text="", fg="red", font=("Arial", 10))
        self.status.pack(pady=10)

        button_frame = tk.Frame(self)
        button_frame.pack(pady=10)

        self.login_button = tk.Button(
            button_frame, 
            text="Login", 
            font=("Arial", 11),
            width=15,
            command=self.primary_action
        )
        self.login_button.pack(side="left", padx=5)

        tk.Button(
            button_frame, 
            text="Back", 
            font=("Arial", 11),
            width=15,
            command=self.app.go_back
        ).pack(side="left", padx=5)

    def primary_action(self):
        try:
            current_time = int(time.time())

            if current_time < self.app.locked_until:
                return

            user = self.app.db.get_master_user()
            if user is None:
                messagebox.showinfo("Info", "No registered user found.\nPlease register first.")
                return

            stored_hash, stored_salt = user
            password = self.password_entry.get()

            result = self.app.db.get_failed_attempt_info()
            if result is None:
                failed_attempts = 0
                last_failed = 0
            else:
                failed_attempts, last_failed = result

            if failed_attempts > 0:
                delay = 2 * (2 ** (failed_attempts - 1))
                elapsed = current_time - last_failed

                if elapsed < delay:
                    remaining = delay - elapsed
                    self.app.locked_until = current_time + remaining
                    self.start_timer()
                    return

            if not self.app.auth.verify_master_password(password, stored_hash, stored_salt):
                self.app.db.record_failed_attempt()
                self.status.config(text=" Incorrect password!", fg="red")
                self.password_entry.delete(0, tk.END)

                failed_attempts += 1
                delay = 2 * (2 ** (failed_attempts - 1))
                self.app.locked_until = current_time + delay
                self.start_timer()
                return

            self.app.db.reset_failed_attempts()

            salt_bytes = bytes.fromhex(stored_salt)
            root_key = self.app.auth.derive_root_key(password, salt_bytes)
            encryption_key = self.app.auth.derive_subkey(root_key, "encryption")

            enc_manager = EncryptionManager(encryption_key)
            self.app.login_success(enc_manager)

        except Exception as e:
            self.status.config(text=f" Error: {str(e)}", fg="red")
            traceback.print_exc()

    def start_timer(self):
        self.login_button.config(state="disabled")
        self.update_timer()

    def update_timer(self):
        try:
            remaining = self.app.locked_until - int(time.time())
            if remaining <= 0:
                self.login_button.config(state="normal")
                self.status.config(text="")
                return

            self.status.config(text=f" Wait: {remaining} seconds", fg="orange")
            self.after(1000, self.update_timer)
        except Exception as e:
            print(f"Timer error: {e}")


# ===================================================
# NOTES LIST FRAME
# ===================================================

class NotesListFrame(tk.Frame):
    def __init__(self, app):
        super().__init__(app.root)
        self.app = app

        tk.Label(self, text=" My Notes", font=("Arial", 18, "bold")).pack(pady=10)

        search_frame = tk.Frame(self)
        search_frame.pack(pady=5)

        self.search_entry = tk.Entry(search_frame, width=30, font=("Arial", 10))
        self.search_entry.pack(side="left", padx=5)

        tk.Button(search_frame, text=" Search", command=self.search_notes).pack(side="left")

        list_frame = tk.Frame(self)
        list_frame.pack(fill="both", expand=True, padx=20, pady=10)

        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")

        self.listbox = tk.Listbox(
            list_frame, 
            yscrollcommand=scrollbar.set,
            font=("Arial", 11),
            selectmode="single"
        )
        self.listbox.pack(fill="both", expand=True)
        scrollbar.config(command=self.listbox.yview)

        button_frame = tk.Frame(self)
        button_frame.pack(pady=10)

        tk.Button(
            button_frame, 
            text=" Add Note", 
            font=("Arial", 10),
            command=self.add_note
        ).pack(side="left", padx=5)

        tk.Button(
            button_frame, 
            text=" Edit", 
            font=("Arial", 10),
            command=self.edit_note
        ).pack(side="left", padx=5)

        tk.Button(
            button_frame, 
            text=" Delete", 
            font=("Arial", 10),
            command=self.delete_note
        ).pack(side="left", padx=5)

        self.load_notes()

    def load_notes(self):
        try:
            self.listbox.delete(0, tk.END)
            self.notes = self.app.db.get_all_notes()

            for note in self.notes:
                self.listbox.insert(tk.END, f" {note[1]}")
        except Exception as e:
            messagebox.showerror("Error", f"Error loading notes:\n{str(e)}")

    def search_notes(self):
        try:
            keyword = self.search_entry.get().strip()
            self.listbox.delete(0, tk.END)

            results = self.app.db.search_notes_by_title(keyword)
            self.notes = results

            for note in results:
                self.listbox.insert(tk.END, f" {note[1]}")
        except Exception as e:
            messagebox.showerror("Error", f"Error searching notes:\n{str(e)}")

    def get_selected_note_id(self):
        selection = self.listbox.curselection()
        if selection:
            index = selection[0]
            return self.notes[index][0]
        return None

    def add_note(self):
        self.app.show_frame(NoteEditorFrame)

    def edit_note(self):
        try:
            note_id = self.get_selected_note_id()
            if note_id:
                self.app.show_frame(NoteEditorFrame, note_id)
            else:
                messagebox.showinfo("Info", "Please select a note to edit.")
        except Exception as e:
            messagebox.showerror("Error", f"Error editing note:\n{str(e)}")

    def delete_note(self):
        try:
            note_id = self.get_selected_note_id()
            if note_id:
                if messagebox.askyesno("Confirm", "Are you sure you want to delete this note?"):
                    self.app.db.delete_note(note_id)
                    self.load_notes()
            else:
                messagebox.showinfo("Info", "Please select a note to delete.")
        except Exception as e:
            messagebox.showerror("Error", f"Error deleting note:\n{str(e)}")


# ===================================================
# NOTE EDITOR FRAME
# ===================================================

class NoteEditorFrame(tk.Frame):
    def __init__(self, app, note_id=None):
        super().__init__(app.root)
        self.app = app
        self.note_id = note_id

        title_frame = tk.Frame(self)
        title_frame.pack(pady=10)

        self.title_var = tk.StringVar()
        self.title_var.set("New Note")

        self.title_label = tk.Label(
            title_frame, 
            textvariable=self.title_var, 
            font=("Arial", 18, "bold"),
            cursor="hand2",
            fg="blue"
        )
        self.title_label.pack()
        self.title_label.bind("<Button-1>", self.edit_title)

        self.title_entry = tk.Entry(title_frame, font=("Arial", 16), width=40)
        self.title_entry.bind("<Return>", self.save_title)
        self.title_entry.bind("<FocusOut>", self.save_title)

        self.text_area = tk.Text(
            self, 
            wrap="word",
            font=("Arial", 11),
            padx=10,
            pady=10
        )
        self.text_area.pack(fill="both", expand=True, padx=20, pady=10)

        button_frame = tk.Frame(self)
        button_frame.pack(pady=10)

        tk.Button(
            button_frame, 
            text=" Save", 
            font=("Arial", 10),
            command=self.save_note
        ).pack(side="left", padx=5)

        tk.Button(
            button_frame, 
            text=" Cancel", 
            font=("Arial", 10),
            command=self.app.go_back
        ).pack(side="left", padx=5)

        if note_id:
            self.load_note(note_id)

    def edit_title(self, event=None):
        try:
            current_title = self.title_var.get()
            if current_title == "New Note":
                current_title = ""

            self.title_entry.delete(0, tk.END)
            self.title_entry.insert(0, current_title)

            self.title_label.pack_forget()
            self.title_entry.pack()
            self.title_entry.focus()
        except Exception as e:
            print(f"Edit title error: {e}")

    def save_title(self, event=None):
        try:
            new_title = self.title_entry.get().strip()
            if new_title:
                self.title_var.set(new_title)
            else:
                self.title_var.set("New Note")

            self.title_entry.pack_forget()
            self.title_label.pack()
        except Exception as e:
            print(f"Save title error: {e}")

    def load_note(self, note_id):
        try:
            note = self.app.db.get_note_by_id(note_id)
            if note:
                _, title, encrypted_content, nonce = note
                decrypted = self.app.encryption_manager.decrypt(encrypted_content, nonce)

                self.title_var.set(title)
                self.text_area.insert("1.0", decrypted)
        except Exception as e:
            messagebox.showerror("Error", f"Error loading note:\n{str(e)}")

    def save_note(self):
        try:
            title = self.title_var.get().strip()
            content = self.text_area.get("1.0", tk.END).strip()

            if not title or title == "New Note":
                messagebox.showwarning("Warning", "Please enter a title.")
                return

            if not content:
                messagebox.showwarning("Warning", "Note content cannot be empty.")
                return

            encrypted_content, nonce = self.app.encryption_manager.encrypt(content)

            if self.note_id:
                self.app.db.update_note(self.note_id, title, encrypted_content, nonce)
            else:
                self.app.db.add_note(title, encrypted_content, nonce)

            self.app.go_back()
        except Exception as e:
            messagebox.showerror("Error", f"Error saving note:\n{str(e)}")
            traceback.print_exc()


# ===================================================
# MAIN - WITH ERROR HANDLING
# ===================================================

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = SecureNotesApp(root)
        root.mainloop()
    except KeyboardInterrupt:
        print("\n Program terminated by user (Ctrl+C)")
        sys.exit(0)
    except Exception as e:
        print(f"\n Unexpected error: {e}")
        traceback.print_exc()
        input("\nPress Enter to close...")
        sys.exit(1)