import os
import sys
import nmap
import ipaddress
from datetime import datetime
from prettytable import PrettyTable
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel, QLineEdit,
    QComboBox, QPushButton, QTableWidget, QTableWidgetItem, QMessageBox, QProgressBar, QHeaderView
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from fpdf import FPDF

class NetworkScanner:
    def __init__(self, target_ip, scan_type="tcp_connect"):
        self.target_ip = target_ip
        self.scan_type = scan_type
        self.result_table = PrettyTable()
        self.result_table.field_names = ["Host", "Status", "Open Ports", "Services", "Operating System"]

    def discover_hosts(self):
        scanner = nmap.PortScanner()
        scanner.scan(self.target_ip, arguments="-sn")
        return scanner.all_hosts()

    def scan_ports(self, target_ip, scan_type):
        scanner = nmap.PortScanner()
        scan_arguments = {
            "tcp_connect": "-sT",
            "tcp_syn": "-sS",
            "udp": "-sU",
        }
        if scan_type not in scan_arguments:
            return None
        scanner.scan(target_ip, arguments=f"{scan_arguments[scan_type]} -O")
        return scanner

    def perform_scan(self, progress_callback=None):
        discovered_hosts = self.discover_hosts()

        if not discovered_hosts:
            return "No hosts discovered."

        total_hosts = len(discovered_hosts)
        for index, host in enumerate(discovered_hosts):
            open_ports, services = [], []
            status, os_info = "unknown", "N/A"

            if self.scan_type == "Default":
                for scan_type in ["tcp_connect", "tcp_syn", "udp"]:
                    scanner = self.scan_ports(host, scan_type)
                    if scanner and host in scanner.all_hosts():
                        status = scanner[host].state()
                        if 'tcp' in scanner[host]:
                            for port in scanner[host]['tcp']:
                                port_info = scanner[host]['tcp'][port]
                                open_ports.append(port)
                                services.append(port_info.get('name', 'Unknown'))
                        if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
                            os_info = ", ".join(
                                f"{os['name']}"
                                for os in scanner[host]['osmatch']
                            )
            else:
                scanner = self.scan_ports(host, self.scan_type)
                if scanner and host in scanner.all_hosts():
                    status = scanner[host].state()
                    if 'tcp' in scanner[host]:
                        for port in scanner[host]['tcp']:
                            port_info = scanner[host]['tcp'][port]
                            open_ports.append(port)
                            services.append(port_info.get('name', 'Unknown'))
                    if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
                        os_info = ", ".join(
                            f"{os['name']}"
                            for os in scanner[host]['osmatch']
                        )

            open_ports_str = ", ".join(map(str, open_ports)) if open_ports else "No open ports"
            services_str = ", ".join(services) if services else "No services"

            self.result_table.add_row([host, status, open_ports_str, services_str, os_info])

            # Update progress bar
            if progress_callback:
                progress = (index + 1) / total_hosts * 100
                progress_callback(int(progress))  # Convert to int here

        return self.result_table

    def get_results_count(self):
        count = {
            "Total Hosts": len(self.result_table.rows),
            "Up Hosts": sum(1 for row in self.result_table.rows if row[1] == "up"),
            "Open Ports": sum(len(row[2].split(", ")) for row in self.result_table.rows if row[2] != "No open ports"),
            "Services": sum(1 for row in self.result_table.rows if row[3] != "No services"),
            "Operating Systems": sum(1 for row in self.result_table.rows if row[4] != "N/A"),
        }
        return count


class ScanThread(QThread):
    progress_signal = pyqtSignal(int)
    result_signal = pyqtSignal(object)
    error_signal = pyqtSignal(str)

    def __init__(self, target_ip, scan_type):
        super().__init__()
        self.target_ip = target_ip
        self.scan_type = scan_type

    def run(self):
        try:
            scanner = NetworkScanner(self.target_ip, self.scan_type)
            result_table = scanner.perform_scan(self.progress_signal.emit)
            self.result_signal.emit(scanner)  # Emit scanner object
        except Exception as e:
            self.error_signal.emit(str(e))


class MatplotlibWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.figure, self.ax = plt.subplots()
        self.canvas = FigureCanvas(self.figure)
        layout = QVBoxLayout()
        layout.addWidget(self.canvas)
        self.setLayout(layout)

    def update_chart(self, results):
        self.ax.clear()
        counts = results.get_results_count()
        self.ax.bar(counts.keys(), counts.values())
        self.ax.set_xlabel("Categories")
        self.ax.set_ylabel("Count")
        self.ax.set_title("Scan Results Overview")
        self.canvas.draw()


class NetworkScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Base Scan")
        self.setGeometry(100, 100, 800, 600)

        layout = QVBoxLayout()

        # Input field for network range
        self.target_ip_label = QLabel("Enter Target IP or Network Range:")
        layout.addWidget(self.target_ip_label)
        self.target_ip_input = QLineEdit()
        layout.addWidget(self.target_ip_input)

        # Scan type button
        self.scan_type_label = QLabel("Select Scan Type:")
        layout.addWidget(self.scan_type_label)
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Default", "tcp_connect", "tcp_syn", "udp"])
        layout.addWidget(self.scan_type_combo)

        # Scan button
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)

        # Progress bar
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        # Button to generate PDF report
        self.download_pdf_button = QPushButton("Download PDF Report", self)
        self.download_pdf_button.clicked.connect(self.generate_pdf_report)
        self.download_pdf_button.setEnabled(False)
        layout.addWidget(self.download_pdf_button)

        # Label to display total open ports , total os , total hosts
        self.total_hosts_label = QLabel("Total Hosts: 0")
        self.open_ports_label = QLabel("Open Ports: 0")
        self.os_label = QLabel("Total OS: 0")
        layout.addWidget(self.total_hosts_label)
        layout.addWidget(self.open_ports_label)
        layout.addWidget(self.os_label)

        # Table to show scan results
        self.result_table = QTableWidget(self)
        self.result_table.setColumnCount(5)
        self.result_table.setHorizontalHeaderLabels(["IP Address", "Host Status", "Open Ports", "Services", "Detected OS"])
        header = self.result_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.result_table)

        # Area for Matplotlib figure
        self.matplotlib_widget = MatplotlibWidget()
        layout.addWidget(self.matplotlib_widget)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.scan_thread = None

    def start_scan(self):
        target_ip = self.target_ip_input.text()
        scan_type = self.scan_type_combo.currentText()

        if not target_ip:
            QMessageBox.warning(self, "Input Error", "Please enter a target IP or network range.")
            return

        try:
            
            ip_network = ipaddress.IPv4Network(target_ip, strict=False)
        except ValueError:
            if '/' in target_ip:
                QMessageBox.warning(self, "Invalid Subnet Mask", "Please enter a valid subnet mask.")
            else:
                QMessageBox.warning(self, "Invalid IP", "Please enter a valid IP address.")
            return

        self.scan_button.setEnabled(False)
        self.target_ip_input.setEnabled(False)
        self.scan_type_combo.setEnabled(False)

        self.scan_thread = ScanThread(target_ip, scan_type)
        self.scan_thread.progress_signal.connect(self.update_progress_bar)
        self.scan_thread.result_signal.connect(self.handle_scan_results)
        self.scan_thread.error_signal.connect(self.handle_scan_error)
        self.scan_thread.start()

    def update_progress_bar(self, value):
        self.progress_bar.setValue(value)

    def handle_scan_results(self, scanner):
        self.update_results_table(scanner.result_table)
        self.update_count_labels(scanner.get_results_count())
        self.matplotlib_widget.update_chart(scanner)
        self.download_pdf_button.setEnabled(True)
        self.scan_button.setEnabled(True)
        self.target_ip_input.setEnabled(True)

    def handle_scan_error(self, error_message):
        QMessageBox.critical(self, "Scan Error", f"An error occurred: {error_message}")
        self.scan_button.setEnabled(True)
        self.target_ip_input.setEnabled(True)
        self.scan_type_combo.setEnabled(False)

    def update_count_labels(self, counts):
        self.total_hosts_label.setText(f"Total Hosts: {counts['Total Hosts']}")
        self.open_ports_label.setText(f"Open Ports: {counts['Open Ports']}")
        self.os_label.setText(f"Total OS: {counts['Operating Systems']}")

    def update_results_table(self, result_table):
        self.result_table.setRowCount(len(result_table.rows))
        for row_idx, row in enumerate(result_table.rows):
            for col_idx, item in enumerate(row):
                table_item = QTableWidgetItem(item)
                table_item.setFlags(table_item.flags() & ~Qt.ItemFlag.ItemIsEditable)  # Make cell non-editable
                table_item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)  # Align text
                self.result_table.setItem(row_idx, col_idx, table_item)
        self.result_table.resizeRowsToContents()  # Adjust row height to fit content


    def generate_pdf_report(self):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        # Add logo
        image_path = r'D:\\Project wahba\\poto.png'
        if os.path.exists(image_path):
            pdf.image(image_path, x=10, y=8, w=30)
        else:
            QMessageBox.warning(self, "Image Error", f"The image file '{image_path}' was not found. Report will be generated without the logo.")

        pdf.cell(200, 10, txt="Base Scan Report", ln=True, align='C')
        current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        pdf.cell(200, 10, txt=f"Report generated on: {current_datetime}", ln=True, align='C')
        pdf.ln(10)

        # Summary Section
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Spiders", ln=True, align="L")
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Scan Summary", ln=True, align="L")
        pdf.set_font("Arial", "", 12)

        total_hosts = self.total_hosts_label.text().split(": ")[1]
        total_os_label = self.os_label.text().split(": ")[1]
        total_open_ports = self.open_ports_label.text().split(": ")[1]

        pdf.cell(0, 10, f"Total Hosts: {total_hosts}", ln=True)
        pdf.cell(0, 10, f"Total OS: {total_os_label}", ln=True)
        pdf.cell(0, 10, f"Total Open Ports: {total_open_ports}", ln=True)
        pdf.ln(5)

        # Add table
        pdf.set_font("Arial", "B", 10)
        header = ["IP Address", "Host Status", "Open Ports", "Services", "Detected OS"]
        column_widths = [25, 15, 40, 50, 50]

        # Add table headers
        for col_idx, header_text in enumerate(header):
            pdf.cell(column_widths[col_idx], 10, header_text, border=1, align="C")
        pdf.ln()

        pdf.set_font("Arial", "", 9)

        # Iterate through table rows
        for row in range(self.result_table.rowCount()):
            cell_texts = []

            # Collect cell content for the current row
            for col_idx in range(self.result_table.columnCount()):
                item = self.result_table.item(row, col_idx)
                text = item.text() if item else ""
                cell_texts.append(text)

            # Determine the maximum number of lines needed for the row
            line_counts = [
                len(pdf.multi_cell(column_widths[col_idx], 10, cell_text, border=0, split_only=True))
                for col_idx, cell_text in enumerate(cell_texts)
            ]
            max_row_height = max(line_counts) * 10  # Calculate the maximum row height

            # Write each cell, maintaining consistent row height
            for col_idx, col_width in enumerate(column_widths):
                x, y = pdf.get_x(), pdf.get_y()
                pdf.multi_cell(col_width, 10, cell_texts[col_idx], border=1, align="C")
                pdf.set_xy(x + col_width, y)  # Move cursor horizontally within the row

            pdf.ln(max_row_height)  # Move to the next row after completing all columns

        pdf.ln(10)

        # Add chart
        self.matplotlib_widget.figure.savefig("scan_results_chart.png", format='png')
        pdf.image("scan_results_chart.png", x=10, y=None, w=190)

        pdf_file_name = f"base_scan_report.pdf"
        pdf.output(pdf_file_name)
        QMessageBox.information(self, "PDF Saved", f"Report saved as {pdf_file_name}")



if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkScannerGUI()
    window.show()
    sys.exit(app.exec())
