import tkinter as tk
import db_utils  # ./db_utils.py
from tkinter import messagebox

__version__ = "1.0"


class MainApplication(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.title("PasswordManager Login")

        self.geometry("400x300")
        self.main_frame = tk.Frame(self)
        container = self.main_frame

        self.frames = {}
        self.last_frame = None

        container.pack(side="top", fill="both", expand=True)

        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.register_frame(LoginFrame)
        self.show_frame(LoginFrame)

    def register_frame(self, screen_cls):
        frame = screen_cls(self.main_frame, self)
        self.frames[screen_cls] = {
            'frame': frame,
            'widgets': {}
        }

    def show_frame(self, cont):
        frame = self.frames.get(cont)

        if not frame:
            return False

        frame['frame'].grid(row=0, column=0, sticky="nsew")
        frame['frame'].tkraise()

        self.last_frame = frame
        return True

    def show_prev_frame(self):
        if not self.last_frame:
            return False

        self.last_frame['frame'].grid(row=0, column=0, sticky="nsew")
        self.last_frame['frame'].tkraise()

        self.last_frame = None
        return True

    def store_widgets(self, cont: tk.Frame, widgets: dict):
        frame = self.frames.get(cont)

        if not frame:
            return False

        frame['widgets'] = widgets


class LoginFrame(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#d3d3d3")
        self.controller = controller

        self.login_widgets = {}
        w = self.login_widgets

        w['Title'] = tk.Label(
            self, text="PasswordManager Login",
            font=("Helvetica", 18),

            bg='#d3d3d3'
        )
        w['Title'].pack(padx=5, pady=5)

        w['UsernameEntry'] = tk.Entry(self, bg='#d3d3d3')
        w['UsernameEntry'].pack(padx=5, pady=5)

        w['PasswordEntry'] = tk.Entry(self, bg='#d3d3d3', show="*")
        w['PasswordEntry'].pack(padx=5, pady=5)

        w['LoginButton'] = tk.Button(
            self, text="Login",
            command=lambda: self._login_call()
        )
        w['LoginButton'].pack(padx=5)

        w['RegisterButton'] = tk.Button(
            self, text="Register",
            command=lambda: self._register_call()
        )
        w['RegisterButton'].pack(padx=5)

        w['LoginStatus'] = tk.Label(
            self, text="",
            font=("Helvetica", 12),

            bg='#d3d3d3'
        )
        w['LoginStatus'].pack(padx=0, pady=5)

    def _login_call(self):
        username = self.login_widgets['UsernameEntry'].get()
        password = self.login_widgets['PasswordEntry'].get()

        try:
            self.user_mgr = db_utils.UserManager(
                username, password
            )
        except (
            db_utils.exceptions.InvalidUserError,
            db_utils.exceptions.InvalidCredentialsError
        ):
            self.login_widgets['LoginStatus'].config(
                text="Invalid username or password!",

                fg='red'
            )
        except db_utils.exceptions.NoCredentialsError:
            self.login_widgets['LoginStatus'].config(
                text="Please enter a username and password.",

                fg='red'
            )
        else:
            self.login_widgets['LoginStatus'].config(
                text="Login successful! Now loading. . .",

                fg='green'
            )
            self._finalize_login()

    def _register_call(self):
        username = self.login_widgets['UsernameEntry'].get()
        password = self.login_widgets['PasswordEntry'].get()

        db_mgr = db_utils.DatabaseManager()

        try:
            db_mgr.create_user(
                username, password
            )
        except db_utils.exceptions.NoCredentialsError:
            self.login_widgets['LoginStatus'].config(
                text="Please enter a username and password.",

                fg='red'
            )
        except db_utils.exceptions.ExistingUserError:
            self.login_widgets['LoginStatus'].config(
                text="Username is already taken!",

                fg='red'
            )
        else:
            self.user_mgr = db_utils.UserManager(
                username, password
            )
            self.login_widgets['LoginStatus'].config(
                text="Register successful! Now loading. . .",

                fg='green'
            )
            self._finalize_login()

    def _finalize_login(self):
        self.controller.user_mgr = self.user_mgr
        self.controller.store_widgets(LoginFrame, self.login_widgets)

        def create_scr():
            self.controller.register_frame(HomeFrame)
            self.controller.show_frame(HomeFrame)

        entry_frames = [
            AddEntryFrame, ModifyEntryFrame,
            GetEntryFrame, DeleteEntryFrame
        ]
        for ScreenClass in entry_frames:
            self.controller.register_frame(ScreenClass)

        self.controller.after(1000, create_scr)  # change to 1500 once developmetn is done


class HomeFrame(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg='#d3d3d3')
        self.controller = controller

        controller.title("PasswordManager v1.0")

        self.user_mgr = controller.user_mgr
        self.home_widgets = {}

        w = self.home_widgets
        self.recent_passwords = self.user_mgr.get_latest(8)

        w['WelcomeTitle'] = tk.Label(
            self, text=f"Welcome, {self.user_mgr.username}.",
            font=("Helvetica", 14),
            bg='#d3d3d3'
        )
        w['AddEntry'] = tk.Button(
            self, text="Add entry into the database",
            bg='#d3d3d3', command=self._add_entry
        )

        w['ModifyEntry'] = tk.Button(
            self, text="Change an entry in the database",
            bg='#d3d3d3', command=self._modify_entry
        )
        w['GetEntry'] = tk.Button(
            self, text="Get an entry in the database",
            bg='#d3d3d3', command=self._get_entry
        )

        w['DeleteEntry'] = tk.Button(
            self, text='Delete an entry in the database',
            bg='#d3d3d3', command=self._delete_entry
        )

        w['WelcomeTitle'].pack(padx=5, pady=5)
        w['AddEntry'].pack(padx=5, pady=5)

        w['ModifyEntry'].pack(padx=5, pady=5)
        w['GetEntry'].pack(padx=5, pady=5)

        w['DeleteEntry'].pack(padx=5, pady=5)

    def _add_entry(self):
        self.controller.show_frame(AddEntryFrame)

    def _modify_entry(self):
        self.controller.show_frame(ModifyEntryFrame)

    def _get_entry(self):
        self.controller.show_frame(GetEntryFrame)

    def _delete_entry(self):
        self.controller.show_frame(DeleteEntryFrame)


class AddEntryFrame(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg='#d3d3d3')
        self.controller = controller

        self.user_mgr = controller.user_mgr
        self.frame_widgets = {}

        w = self.frame_widgets
        w['AddEntryLabel'] = tk.Label(
            self,
            text=f"Add an entry to the database",
            font=("Helvetica", 12),
            bg='#d3d3d3'
        )
        w['AddEntryLabel_PWTitle'] = tk.Label(
            self,
            text=f"Password Title:",
            font=("Helvetica", 12),
            bg='#d3d3d3'
        )

        w['AddEntryInput_1'] = tk.Entry(self)
        w['AddEntryLabel_PWData'] = tk.Label(
            self,
            text=f"Password Data:",
            font=("Helvetica", 12),
            bg='#d3d3d3'
        )

        w['AddEntryInput_2'] = tk.Entry(
            self,
            show="*"
        )

        w['AddEntrySubmit'] = tk.Button(
            self, bg='#d3d3d3',
            text='Add entry',
            command=self._add_entry
        )

        w['AddEntryReturn'] = tk.Button(
            self, bg='#d3d3d3',
            text='Return to home',
            command=self._return_home
        )

        w['AddEntryStatus'] = tk.Label(
            self, text="",
            font=("Helvetica", 12),

            bg='#d3d3d3'
        )

        w['AddEntryInput_1'].bind(
            '<Return>',
            lambda *_: self._widget_events('entry-return1')
        )
        w['AddEntryInput_2'].bind(
            '<Return>',
            lambda *_: self._widget_events('entry-return2')
        )

        w['AddEntryLabel'].grid(row=1, column=0, padx=5, pady=5, sticky='w')
        w['AddEntryLabel_PWTitle'].grid(row=2, column=0, padx=5, pady=5, sticky='w')

        w['AddEntryInput_1'].grid(row=2, column=1, padx=5, pady=5, sticky='w')
        w['AddEntryLabel_PWData'].grid(row=3, column=0, padx=5, pady=5, sticky='w')

        w['AddEntryInput_2'].grid(row=3, column=1, padx=5, pady=5, sticky='w')
        w['AddEntrySubmit'].grid(row=4, column=0, padx=5, pady=5, sticky='w')

        w['AddEntryReturn'].grid(row=5, column=0, padx=5, pady=5, sticky='w')
        w['AddEntryStatus'].grid(row=6, column=0, padx=5, pady=5, sticky='s')

    def _add_entry(self):
        w = self.frame_widgets

        pw_title = w['AddEntryInput_1'].get()
        pw_data = w['AddEntryInput_2'].get()

        if not pw_title or not pw_data:
            w['AddEntryStatus'].config(
                text="Please enter a password title\n and the password.",
                fg='red'
            )
            return

        try:
            self.user_mgr.add_entry(pw_title, pw_data)
        except db_utils.exceptions.DataExistsError:
            w['AddEntryStatus'].config(
                text="Entry already exists\n in the database!",
                fg='red'
            )
        else:
            w['AddEntryStatus'].config(
                text="Entry added successfully!",
                fg='green'
            )

    def _widget_events(self, event_type: str):
        w = self.frame_widgets
        match event_type:
            case "entry-return1":
                w['AddEntryInput_2'].focus()
            case "entry-return2":
                self.focus()
                self._add_entry()
            case _:
                raise RuntimeError("Invalid widget event type")

    def _return_home(self):
        self.controller.show_frame(HomeFrame)


class ModifyEntryFrame(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg='#d3d3d3')
        self.controller = controller

        self.user_mgr = controller.user_mgr
        self.frame_widgets = {}

        w = self.frame_widgets
        w['ModifyEntryLabel'] = tk.Label(
            self,
            text=f"Change an entry in the database",
            font=("Helvetica", 12),
            bg='#d3d3d3'
        )
        w['ModifyEntryLabel_PWTitle'] = tk.Label(
            self,
            text=f"Password Title:",
            font=("Helvetica", 12),
            bg='#d3d3d3'
        )

        w['ModifyEntryInput_1'] = tk.Entry(self)
        w['ModifyEntryLabel_PWData'] = tk.Label(
            self,
            text=f"Password Data:",
            font=("Helvetica", 12),
            bg='#d3d3d3'
        )

        w['ModifyEntryInput_2'] = tk.Entry(
            self,
            show="*"
        )

        w['ModifyEntrySubmit'] = tk.Button(
            self, bg='#d3d3d3',
            text='Modify entry',
            command=self._modify_entry
        )

        w['ModifyEntryReturn'] = tk.Button(
            self, bg='#d3d3d3',
            text='Return to home',
            command=self._return_home
        )

        w['ModifyEntryStatus'] = tk.Label(
            self, text="",
            font=("Helvetica", 12),

            bg='#d3d3d3'
        )

        w['ModifyEntryInput_1'].bind(
            '<Return>',
            lambda *_: self._widget_events('entry-return1')
        )
        w['ModifyEntryInput_2'].bind(
            '<Return>',
            lambda *_: self._widget_events('entry-return2')
        )

        w['ModifyEntryLabel'].grid(row=1, column=0, padx=5, pady=5, sticky='w')
        w['ModifyEntryLabel_PWTitle'].grid(row=2, column=0, padx=5, pady=5, sticky='w')

        w['ModifyEntryInput_1'].grid(row=2, column=1, padx=5, pady=5, sticky='w')
        w['ModifyEntryLabel_PWData'].grid(row=3, column=0, padx=5, pady=5, sticky='w')

        w['ModifyEntryInput_2'].grid(row=3, column=1, padx=5, pady=5, sticky='w')
        w['ModifyEntrySubmit'].grid(row=4, column=0, padx=5, pady=5, sticky='w')

        w['ModifyEntryReturn'].grid(row=5, column=0, padx=5, pady=5, sticky='w')
        w['ModifyEntryStatus'].grid(row=6, column=0, padx=5, pady=5, sticky='s')

    def _modify_entry(self):
        w = self.frame_widgets

        pw_title = w['ModifyEntryInput_1'].get()
        pw_data = w['ModifyEntryInput_2'].get()

        if not pw_title or not pw_data:
            w['ModifyEntryStatus'].config(
                text="Please enter a password title\n and the password.",
                fg='red'
            )
            return

        try:
            self.user_mgr.modify_entry(pw_title, pw_data)
        except db_utils.exceptions.NoDataError:
            w['ModifyEntryStatus'].config(
                text="Entry doesn't exist\n in the database!",
                fg='red'
            )
        else:
            w['ModifyEntryStatus'].config(
                text="Entry changed successfully!",
                fg='green'
            )

    def _widget_events(self, event_type: str):
        w = self.frame_widgets
        match event_type:
            case "entry-return1":
                w['ModifyEntryInput_2'].focus()
            case "entry-return2":
                self.focus()
                self._modify_entry()
            case _:
                raise RuntimeError("Invalid widget event type")

    def _return_home(self):
        self.controller.show_frame(HomeFrame)


class GetEntryFrame(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg='#d3d3d3')
        self.controller = controller

        self.user_mgr = controller.user_mgr
        self.frame_widgets = {}

        w = self.frame_widgets
        w['GetEntryLabel'] = tk.Label(
            self,
            text=f"Get an entry in the database",
            font=("Helvetica", 12),
            bg='#d3d3d3'
        )
        w['GetEntryLabel_PWTitle'] = tk.Label(
            self,
            text=f"Password Title:",
            font=("Helvetica", 12),
            bg='#d3d3d3'
        )

        w['GetEntryInput_1'] = tk.Entry(self)

        w['GetEntrySubmit'] = tk.Button(
            self, bg='#d3d3d3',
            text='Get entry',
            command=self._get_entry
        )

        w['GetEntryReturn'] = tk.Button(
            self, bg='#d3d3d3',
            text='Return to home',
            command=self._return_home
        )

        w['GetEntryStatus'] = tk.Label(
            self, text="",
            font=("Helvetica", 12),

            bg='#d3d3d3'
        )

        w['GetEntryData'] = tk.Label(
            self, text="",
            font=("Helvetica", 12),

            bg='#d3d3d3'
        )

        w['GetEntryDataVisibility'] = tk.Button(
            self, text="Show password",
            command=self._toggle_visibility
        )
        w['GetEntryCopyPassword'] = tk.Button(
            self, text='Copy password',
            command=lambda *_: self._widget_events('copy-password')
        )

        w['GetEntryInput_1'].bind(
            '<Return>',
            lambda *_: self._widget_events('entry-return')
        )

        w['GetEntryLabel'].grid(row=1, column=0, padx=5, pady=5, sticky='w')
        w['GetEntryLabel_PWTitle'].grid(row=2, column=0, padx=5, pady=5, sticky='w')

        w['GetEntryInput_1'].grid(row=2, column=1, padx=5, pady=5, sticky='w')
        w['GetEntrySubmit'].grid(row=3, column=0, padx=5, pady=5, sticky='w')

        w['GetEntryReturn'].grid(row=4, column=0, padx=5, pady=5, sticky='w')
        w['GetEntryStatus'].grid(row=5, column=0, padx=5, pady=5, sticky='s')

    def _get_entry(self):
        w = self.frame_widgets

        pw_title = w['GetEntryInput_1'].get()

        if not pw_title:
            w['GetEntryStatus'].config(
                text="Please enter a password.",
                fg='red'
            )
            return

        self._fetched_data = self.user_mgr.get_entry(pw_title)

        if self._fetched_data is None:
            w['GetEntryStatus'].config(
                text="Entry doesn't exist\n in the database!",
                fg='red'
            )
            return

        w['GetEntryStatus'].config(
            text=f"Fetched '{pw_title}':",
            fg='green'
        )
        w['GetEntryData'].config(
            text=f"{'*' * len(self._fetched_data)}"
        )

        w['GetEntryData'].grid(row=6, column=0, padx=5, pady=5, sticky='s')
        w['GetEntryDataVisibility'].grid(
            row=7, column=0, padx=5,
            pady=5, sticky='s'
        )

        w['GetEntryCopyPassword'].grid(
            row=8, column=0, padx=5,
            pady=5, sticky='s'
        )

    def _toggle_visibility(self):
        w = self.frame_widgets
        match w['GetEntryDataVisibility'].cget("text"):
            case "Show password":
                w['GetEntryDataVisibility'].config(
                    text='Hide password'
                )
                w['GetEntryData'].config(
                    text=self._fetched_data
                )
            case "Hide password":
                w['GetEntryDataVisibility'].config(
                    text='Show password'
                )
                w['GetEntryData'].config(
                    text=f"{'*' * len(self._fetched_data)}"
                )
            case _:
                messagebox.showerror(
                    "PasswordManager",
                    "An error occured. Details:\n"
                    
                    "w['GetEntryDataVisibility'].cget('text') "
                    "did not return 'Show password' or 'Hide password'"
                )

    def _widget_events(self, event_type: str):
        match event_type:
            case "entry-return":
                self.focus()
                self._get_entry()
            case "copy-password":
                self.clipboard_clear()  # Clear the clipboard
                self.clipboard_append(self._fetched_data)

                messagebox.showinfo(
                    "PasswordManager Copy Password",
                    "Password copied to clipboard!"
                )
            case _:
                raise RuntimeError("Invalid widget event type")

    def _return_home(self):
        w = self.frame_widgets
        self._fetched_data = ""

        w['GetEntryData'].config(
            text=""
        )
        w['GetEntryData'].grid_forget()

        w['GetEntryDataVisibility'].grid_forget()
        w['GetEntryStatus'].config(
            text=""
        )
        self.controller.show_frame(HomeFrame)


class DeleteEntryFrame(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg='#d3d3d3')
        self.controller = controller

        self.user_mgr = controller.user_mgr
        self.frame_widgets = {}

        self._confirm_delete = False

        w = self.frame_widgets
        w['DeleteEntryLabel'] = tk.Label(
            self,
            text=f"Delete an entry in the database",
            font=("Helvetica", 12),
            bg='#d3d3d3'
        )
        w['DeleteEntryLabel_PWTitle'] = tk.Label(
            self,
            text=f"Password Title:",
            font=("Helvetica", 12),
            bg='#d3d3d3'
        )

        w['DeleteEntryInput_1'] = tk.Entry(self)

        w['DeleteEntrySubmit'] = tk.Button(
            self, bg='#d3d3d3',
            text='Delete entry',
            command=self._delete_entry
        )

        w['DeleteEntryReturn'] = tk.Button(
            self, bg='#d3d3d3',
            text='Return to home',
            command=self._return_home
        )

        w['DeleteEntryStatus'] = tk.Label(
            self, text="",
            font=("Helvetica", 12),

            bg='#d3d3d3'
        )

        w['DeleteEntryInput_1'].bind(
            "<Return>",
            lambda *_: self._widget_events('entry-return1')
        )

        w['DeleteEntryLabel'].grid(row=1, column=0, padx=5, pady=5, sticky='w')
        w['DeleteEntryLabel_PWTitle'].grid(row=2, column=0, padx=5, pady=5, sticky='w')

        w['DeleteEntryInput_1'].grid(row=2, column=1, padx=5, pady=5, sticky='w')
        w['DeleteEntrySubmit'].grid(row=3, column=0, padx=5, pady=5, sticky='w')

        w['DeleteEntryReturn'].grid(row=4, column=0, padx=5, pady=5, sticky='w')
        w['DeleteEntryStatus'].grid(row=5, column=0, padx=5, pady=5, sticky='w')

    def _delete_entry(self):
        w = self.frame_widgets
        pw_title = w['DeleteEntryInput_1'].get()

        if not pw_title:
            w['DeleteEntryStatus'].config(
                text="Please enter a password title.",
                fg='red'
            )
            return

        self._fetched_data = self.user_mgr.get_entry(pw_title)

        if self._fetched_data is None:
            w['DeleteEntryStatus'].config(
                text="Entry doesn't exist\n in the database!",
                fg='red'
            )
            return

        if not self._confirm_delete:
            w['DeleteEntryStatus'].config(
                text="This will permanently\ndelete the data \nin"
                " the database. Confirm by pressing\n the "
                
                "delete entry button.",
                fg='red'
            )
            self._confirm_delete = True
            return

        self.user_mgr.delete_entry(pw_title)
        w['DeleteEntryStatus'].config(
            text=f"Deleted '{pw_title}'",
            fg='green'
        )

    def _widget_events(self, event_type: str):
        w = self.frame_widgets
        match event_type:
            case "entry-return1":
                self._delete_entry()
                w['DeleteEntryInput_1'].bind(
                    "<Return>",
                    lambda *_: self._widget_events('entry-return2')
                )
            case "entry-return2":
                self.focus()
                self._delete_entry()
            case _:
                raise RuntimeError("Invalid widget event type")

    def _return_home(self):
        w = self.frame_widgets

        self._confirm_delete = False
        w['DeleteEntryStatus'].config(
            text=""
        )
        self.controller.show_frame(HomeFrame)


if __name__ == "__main__":
    app = MainApplication()
    app.mainloop()
