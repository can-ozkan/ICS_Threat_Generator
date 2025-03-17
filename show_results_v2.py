import tkinter as tk
from tkinter import ttk, filedialog

class ShowResultsApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Analysis Results")
        self.root.geometry("800x600")

        # Create the notebook (tabbed interface)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both")

        # Read the threat data from the file
        threat_data = self.read_threat_data()

        # If there is data, create tabs
        if threat_data:
            for title, threats in threat_data.items():
                self.create_tab(title, threats)
        else:
            self.show_error("No threat data found.")

    def read_threat_data(self):
        """Read and parse the threat data from a file."""
        file_path = filedialog.askopenfilename(title="Select Threat Data File", filetypes=[("Text Files", "*.txt")])
        if not file_path:
            return None

        threat_data = {}
        current_group = None
        with open(file_path, "r") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                if "Threats" in line:
                    current_group = line
                    threat_data[current_group] = []
                elif current_group:
                    if line.startswith("CWE-"):
                        threat_data[current_group].append(line)
        return threat_data

    def create_tab(self, title, threats):
        """Create a new tab with a list of threats."""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=title)

        # Create a text widget to display the threats
        text_widget = tk.Text(frame, wrap="word", height=10)
        text_widget.pack(expand=True, fill="both")

        # Insert the threats into the text widget
        text_widget.insert(tk.END, f"{title}\n" + "-" * len(title) + "\n")
        for threat in threats:
            text_widget.insert(tk.END, f"{threat}\n")

        # Disable the text widget to make it read-only
        text_widget.config(state="disabled")

    def show_error(self, message):
        """Display an error message in the main window."""
        error_frame = ttk.Frame(self.root)
        error_frame.pack(expand=True, fill="both")

        error_label = tk.Label(error_frame, text=message, fg="red")
        error_label.pack(pady=20)

# Create the application window
if __name__ == "__main__":
    root = tk.Tk()
    app = ShowResultsApp(root)
    root.mainloop()
