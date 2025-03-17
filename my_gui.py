import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import json
import sys

import final_app


class ThreatModelingTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Threat Modeling Tool")
        self.root.geometry("1000x600")

        # Create the menu bar
        self.create_menu()

        # Create a toolbar with buttons
        self.create_toolbar()

        # Create a canvas area for diagramming
        self.create_canvas()

        # Create a side panel for components and description
        self.create_component_panel()


        # Create a list to store added components
        self.components = []
        self.canvas_items = []  # Store canvas objects for components
        self.drag_data = {"x": 0, "y": 0, "item": None}  # Track the item being dragged

        # Stack for undo operations
        self.undo_stack = []

    def create_menu(self):
        menubar = tk.Menu(self.root)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Model", command=self.new_model)
        file_menu.add_command(label="Open Model", command=self.open_model)
        file_menu.add_command(label="Save Model", command=self.save_model)
        file_menu.add_command(label="Update Threats",
                              command=self.update_threat_list)  # New Update button
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        # Edit menu
        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Undo", command=self.undo)
        menubar.add_cascade(label="Edit", menu=edit_menu)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Help", command=self.show_help)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menubar)

    def create_toolbar(self):
        toolbar = tk.Frame(self.root, bd=1, relief=tk.RAISED)

        new_button = tk.Button(toolbar, text="New", command=self.new_model)
        new_button.pack(side=tk.LEFT, padx=2, pady=2)

        save_button = tk.Button(toolbar, text="Save", command=self.save_model)
        save_button.pack(side=tk.LEFT, padx=2, pady=2)

        undo_button = tk.Button(toolbar, text="Undo", command=self.undo)
        undo_button.pack(side=tk.LEFT, padx=2, pady=2)

        generate_report_button = tk.Button(toolbar, text="Generate Report", command=self.generate_report)
        generate_report_button.pack(side=tk.LEFT, padx=2, pady=2)

        analyze_button = tk.Button(toolbar, text="Analyze", command=self.analyze_components)  # New Analyze button
        analyze_button.pack(side=tk.LEFT, padx=2, pady=2)

        show_results_button = tk.Button(toolbar, text="Show Results", command=self.show_results)
        show_results_button.pack(side=tk.LEFT, padx=2, pady=2)

        update_button = tk.Button(toolbar, text="Update Threat List", command=self.update_threat_list)
        update_button.pack(side=tk.LEFT, padx=2, pady=2)

        toolbar.pack(side=tk.TOP, fill=tk.X)

    def create_canvas(self):
        self.canvas = tk.Canvas(self.root, bg="white", width=600, height=400)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Bind mouse events for dragging
        self.canvas.bind("<ButtonPress-1>", self.on_canvas_click)
        self.canvas.bind("<B1-Motion>", self.on_canvas_drag)
        self.canvas.bind("<ButtonRelease-1>", self.on_canvas_release)

    def create_component_panel(self):
        # Side panel for component and description input
        side_panel = tk.Frame(self.root, width=300, bg="lightgray")
        side_panel.pack(side=tk.RIGHT, fill=tk.Y)

        component_label = tk.Label(side_panel, text="Add/Edit Component", bg="lightgray")
        component_label.pack(pady=10)

        tk.Label(side_panel, text="Select Known Component:", bg="lightgray").pack(anchor="w", padx=10)

        # Known components dropdown (Combobox)
        self.known_components = ["PLC", "IED", "RTU", "Sensor", "Actuator", "Historian", "Actuator", "Windows Server",
                                 "Embedded Linux", "Scada", "HMI"]
        self.component_dropdown = ttk.Combobox(side_panel, values=self.known_components)
        self.component_dropdown.pack(fill=tk.X, padx=10)

        # Entry for custom component name
        tk.Label(side_panel, text="Or Enter Custom Component Name:", bg="lightgray").pack(anchor="w", padx=10)
        self.component_name_entry = tk.Entry(side_panel)
        self.component_name_entry.pack(fill=tk.X, padx=10)

        tk.Label(side_panel, text="Description:", bg="lightgray").pack(anchor="w", padx=10)
        self.component_description = tk.Text(side_panel, height=5)
        self.component_description.pack(fill=tk.X, padx=10, pady=5)

        add_button = tk.Button(side_panel, text="Add Component", command=self.add_component)
        add_button.pack(pady=10)

        # Listbox to display added components
        self.component_listbox = tk.Listbox(side_panel, height=10)
        self.component_listbox.pack(fill=tk.BOTH, padx=10, pady=10, expand=True)

    def add_component(self):
        # Get the selected component from dropdown or custom component name
        selected_component = self.component_dropdown.get()
        custom_component_name = self.component_name_entry.get()

        # Ensure either a dropdown selection or custom name is provided, not both
        if selected_component and custom_component_name:
            messagebox.showerror("Error",
                                 "Please either select a component from the dropdown or enter a custom component name, not both.")
            return
        elif not selected_component and not custom_component_name:
            messagebox.showerror("Error",
                                 "Please select a component from the dropdown or enter a custom component name.")
            return

        # Determine the final component name to use
        name = selected_component if selected_component else custom_component_name
        description = self.component_description.get("1.0", tk.END).strip()

        if not name or not description:
            messagebox.showerror("Error", "Please fill in both Component and Description.")
            return

        # Add component to the internal list
        self.components.append({"name": name, "description": description})

        # Update the Listbox to display added components
        self.component_listbox.insert(tk.END, f"Component: {name}")

        # Clear the input fields after adding the component
        self.component_name_entry.delete(0, tk.END)
        self.component_description.delete("1.0", tk.END)

        # Create a rectangle to represent the component on the canvas
        self.create_component_rectangle(name)

        # Add the action to the undo stack (store the component name and canvas items)
        self.undo_stack.append(("add_component", name))
        print(self.components)

    def analyze_components(self):
        """Call the analyze.py script and pass the component_list."""
        if not self.components:
            messagebox.showinfo("Info", "No components to analyze.")
            return

        # Serialize the component_list into JSON string for passing to another script
        serialized_list = json.dumps(self.components)

        try:
            # Call the second script 'analyze.py' and pass the serialized component_list
            # subprocess.run(["python", "analyze.py", serialized_list])
            # subprocess.Popen(["python", "analyze.py", serialized_list])

            # Popen is necessary for matplotlib
            subprocess.Popen(["python", "final_app.py", serialized_list])

            # To capture the output, Python >= 3.7 only

            """"
            result = subprocess.run(
                ["python", "final_app.py", serialized_list],
                capture_output=True, text=True
            )

            if result.stderr:
                print("Error:", result.stderr)
                messagebox.showerror("Error", f"Failed to analyze components: {result.stderr}")
                return

            # Capture the output from analyze.py
            output = result.stdout.strip()

            # Parse the output (which should be JSON)
            analysis_results = json.loads(output)

            # Show the analysis results in a second window
            self.show_results_window(analysis_results)
            """


        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze components: {str(e)}")

    def show_results(self):
        """Launch the analysis_output_gui.py script to show the analysis results."""
        try:
            # Use subprocess to launch the analysis_output_gui.py script
            subprocess.Popen(["python", "show_results_v2.py"])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open results window: {str(e)}")


    def update_threat_list(self):
        """Placeholder for the update vulnerability list functionality."""
        try:
            final_app.update_threat_list()
            messagebox.showinfo("Update Complete", "Vulnerability list has been updated.")
        except Exception as e:
            messagebox.showerror("Update Failed", f"An error occurred while updating: {str(e)}")


    def show_results_window(self, results):
        """Display the analysis results in a new window."""
        results_window = tk.Toplevel(self.root)
        results_window.title("Analysis Results")
        results_window.geometry("400x400")

        # Display the results in a readable format
        result_text = tk.Text(results_window, wrap="word")
        result_text.pack(expand=True, fill="both")

        for component, analysis in results.items():
            result_text.insert(tk.END, f"Component: {component}\n")
            result_text.insert(tk.END, f"Result: {analysis}\n")
            result_text.insert(tk.END, "------------------------\n")

        result_text.config(state="disabled")  # Make the text read-only

    def create_component_rectangle(self, name):
        # Determine the position for the next rectangle based on the number of items
        x1, y1 = 50, 50 + (len(self.canvas_items) * 60)  # Positioning rectangles vertically
        x2, y2 = x1 + 100, y1 + 40  # Fixed width and height for the rectangles

        # Create a rectangle and text on the canvas and group them using a tag
        group_tag = f"component_{len(self.canvas_items)}"  # Create a unique tag for each component group
        rect = self.canvas.create_rectangle(x1, y1, x2, y2, fill="lightblue", tags=group_tag)
        label = self.canvas.create_text((x1 + x2) // 2, (y1 + y2) // 2, text=name, tags=group_tag)

        # Store the canvas items (rectangle and text) in a list for reference
        self.canvas_items.append((rect, label))

    def on_canvas_click(self, event):
        # Record the item that the user clicked on
        item = self.canvas.find_closest(event.x, event.y)[0]
        tags = self.canvas.gettags(item)
        if tags:
            self.drag_data["item"] = tags[0]  # Store the tag of the clicked item
            self.drag_data["x"] = event.x
            self.drag_data["y"] = event.y

    def on_canvas_drag(self, event):
        # Move the group (both rectangle and text) based on the recorded tag
        dx = event.x - self.drag_data["x"]
        dy = event.y - self.drag_data["y"]

        if self.drag_data["item"]:
            self.canvas.move(self.drag_data["item"], dx, dy)

        # Update the drag data
        self.drag_data["x"] = event.x
        self.drag_data["y"] = event.y

    def on_canvas_release(self, event):
        # Reset the drag data
        self.drag_data["item"] = None
        self.drag_data["x"] = 0
        self.drag_data["y"] = 0

    def undo(self):
        """Undo the last action."""
        if not self.undo_stack:
            messagebox.showinfo("Undo", "No actions to undo.")
            return

        last_action = self.undo_stack.pop()

        # Undo component addition
        if last_action[0] == "add_component":
            name = last_action[1]

            # Remove from the component list and listbox
            self.components = [comp for comp in self.components if comp["name"] != name]
            listbox_index = self.component_listbox.get(0, tk.END).index(f"Component: {name}")
            self.component_listbox.delete(listbox_index)

            # Remove the corresponding rectangle and label from the canvas
            tag_to_remove = f"component_{listbox_index}"
            self.canvas.delete(tag_to_remove)
            self.canvas_items.pop()

    def new_model(self):
        # Logic for creating a new model
        self.canvas.delete("all")  # Clear the canvas
        self.components.clear()  # Clear the list of components
        self.component_listbox.delete(0, tk.END)  # Clear the Listbox
        self.canvas_items.clear()  # Clear the list of canvas items
        self.undo_stack.clear()  # Clear the undo stack
        messagebox.showinfo("New Model", "New threat model created.")

    def open_model(self):
        # Logic to open a saved threat model file
        file_path = filedialog.askopenfilename(filetypes=[("Threat Model Files", "*.json")])
        if file_path:
            print(f"Opening model from {file_path}")
            # Add your file-opening logic here

    def save_model(self):
        # Logic to save the current threat model
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("Threat Model Files", "*.json")])
        if file_path:
            print(f"Saving model to {file_path}")
            # Add your file-saving logic here

    def generate_report(self):
        # Logic to generate a threat model report
        messagebox.showinfo("Generate Report", "Report generated successfully.")

    def show_help(self):
        # Logic to show help
        messagebox.showinfo("Help", "Help content goes here.")

    def show_about(self):
        # Logic to show about information
        messagebox.showinfo("About", "Threat Modeling Tool\nVersion 1.0")

# Create the application window
root = tk.Tk()
app = ThreatModelingTool(root)

# Start the Tkinter main loop
root.mainloop()
