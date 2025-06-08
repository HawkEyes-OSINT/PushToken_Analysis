import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk
import webbrowser
import os

def analyze_push_token(token):
    token = token.strip()
    if not token:
        return {"error": "No token provided"}
    if len(token) == 64 and all(c in "0123456789abcdefABCDEF" for c in token):
        return {
            "provider": "Apple Push Notification Service (APNs)",
            "platform": "iOS/macOS/watchOS/tvOS",
            "token_type": "Device Token",
            "token_length": len(token),
            "confidence": "High",
            "characteristics": [
                "32-byte binary value represented as hex",
                "Tied to specific app and device combination",
                "Opaque identifier - no extractable metadata"
            ]
        }
    elif ':' in token and len(token) > 100:
        return {
            "provider": "Firebase Cloud Messaging (FCM)",
            "platform": "Android/Web",
            "token_type": "Registration Token",
            "token_length": len(token),
            "confidence": "High",
            "characteristics": [
                "Base64-encoded with delimiters",
                "Refreshed periodically for security",
                "Tied to app instance on device",
                "Contains APA91b prefix (common in FCM)" if "APA91b" in token else ""
            ]
        }
    return {"provider": "Unknown", "token_length": len(token), "confidence": "Low", "characteristics": ["Unrecognized format"]}

class PushTokenAnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Push Token Analyzer - HawkEyes OSINT")
        self.geometry("520x670")
        self.configure(bg="#23272e")
        self.resizable(False, False)

        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('TButton', font=('Segoe UI', 12), background='#1e90ff', foreground='white')
        style.configure('TLabel', background='#23272e', foreground='white', font=('Segoe UI', 11))
        style.configure('Header.TLabel', font=('Segoe UI', 18, 'bold'), background='#23272e', foreground='#1e90ff')

        # Logo
        logo_path = os.path.join(os.path.dirname(__file__), "2.png")
        try:
            logo_img = Image.open(logo_path)
            logo_img = logo_img.resize((320, 120), Image.LANCZOS)
            self.logo = ImageTk.PhotoImage(logo_img)
            logo_label = tk.Label(self, image=self.logo, bg="#23272e")
            logo_label.pack(pady=(20, 10))
        except Exception as e:
            logo_label = tk.Label(self, text="[Logo missing]", bg="#23272e", fg="red")
            logo_label.pack(pady=(20, 10))

        # Title
        title = ttk.Label(self, text="Push Token Analyzer", style='Header.TLabel')
        title.pack(pady=(0, 10))

        # Token input
        self.token_entry = tk.Text(self, height=4, width=55, font=("Segoe UI", 12), bg="#2c313c", fg="white", insertbackground="white", borderwidth=2, relief="groove")
        self.token_entry.pack(pady=(10, 10))
        self.token_entry.insert("1.0", "")

        # Analyze button
        analyze_btn = ttk.Button(self, text="Analyze", command=self.analyze_token)
        analyze_btn.pack(pady=(5, 10))

        # Results
        self.result_box = tk.Text(self, height=12, width=62, font=("Consolas", 10), state="disabled", wrap="word", bg="#181a20", fg="#00ff99", borderwidth=2, relief="groove")
        self.result_box.pack(pady=(10, 10))

        # Spacer
        tk.Label(self, text="", bg="#23272e").pack(pady=(0, 5))

        # Links (website and email)
        link_frame = tk.Frame(self, bg="#23272e")
        link_frame.pack(pady=(0, 15))

        website_link = tk.Label(link_frame, text="Visit hawk-eyes.io", fg="#1e90ff", bg="#23272e", cursor="hand2", font=('Segoe UI', 11, 'underline'))
        website_link.pack(side="left", padx=10)
        website_link.bind("<Button-1>", lambda e: webbrowser.open("https://hawk-eyes.io"))

        email_link = tk.Label(link_frame, text="Contact Support", fg="#1e90ff", bg="#23272e", cursor="hand2", font=('Segoe UI', 11, 'underline'))
        email_link.pack(side="left", padx=10)
        email_link.bind("<Button-1>", lambda e: webbrowser.open("mailto:customer_service@hawk-eyes.io"))

    def analyze_token(self):
        token = self.token_entry.get("1.0", "end").strip()
        result = analyze_push_token(token)
        self.result_box.config(state="normal")
        self.result_box.delete("1.0", "end")
        if "error" in result:
            self.result_box.insert("end", f"Error: {result['error']}\n")
        else:
            for k, v in result.items():
                if isinstance(v, list):
                    self.result_box.insert("end", f"{k.capitalize()}:\n")
                    for item in v:
                        if item:
                            self.result_box.insert("end", f"  - {item}\n")
                else:
                    self.result_box.insert("end", f"{k.capitalize()}: {v}\n")
        self.result_box.config(state="disabled")

if __name__ == "__main__":
    app = PushTokenAnalyzerApp()
    app.mainloop()