from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                           QHBoxLayout, QLabel, QPushButton, QFrame, QTabWidget,
                           QTableWidget, QTableWidgetItem, QScrollArea, QProgressBar,
                           QHeaderView, QGroupBox, QGridLayout)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QMutex
from PyQt6.QtGui import QFont, QColor
import sys
from hardware_detector import HardwareDetector

class StatusUpdateThread(QThread):
    status_updated = pyqtSignal(dict)

    def __init__(self, detector):
        super().__init__()
        self.detector = detector
        self.running = True
        self.paused = False
        self.pause_lock = QMutex()

    def run(self):
        while self.running:
            if not self.paused:
                status = self.detector.get_all_status()
                self.status_updated.emit(status)
            self.msleep(5000)  # Sleep for 5 seconds regardless of pause state

    def stop(self):
        self.running = False
        
    def pause(self):
        self.pause_lock.lock()
        self.paused = True
        self.pause_lock.unlock()
        
    def resume(self):
        self.pause_lock.lock()
        self.paused = False
        self.pause_lock.unlock()
        
    def is_paused(self):
        return self.paused

class StatusFrame(QFrame):
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Raised)
        self.setLineWidth(2)
        
        layout = QVBoxLayout()
        
        # Title
        title_label = QLabel(title)
        title_label.setFont(QFont('Arial', 12, QFont.Weight.Bold))
        layout.addWidget(title_label)
        
        # Status
        self.status_label = QLabel("Checking...")
        self.status_label.setFont(QFont('Arial', 10))
        layout.addWidget(self.status_label)
        
        # Details
        self.details_label = QLabel("")
        self.details_label.setFont(QFont('Arial', 9))
        layout.addWidget(self.details_label)
        
        self.setLayout(layout)
        
    def update_status(self, status_data: dict):
        status = status_data.get('status', 'Unknown')
        self.status_label.setText(f"Status: {status}")
        
        # Set color based on status
        if status in ['Enabled', 'Ready', 'OK']:
            self.setStyleSheet("QFrame { border: 2px solid green; }")
        elif status in ['Disabled', 'Not Ready', 'Warning']:
            self.setStyleSheet("QFrame { border: 2px solid red; }")
        elif status == 'Monitoring':
            self.setStyleSheet("QFrame { border: 2px solid blue; }")
        else:
            self.setStyleSheet("QFrame { border: 2px solid orange; }")
        
        # Update details
        details = []
        for key, value in status_data.items():
            if key != 'status' and key != 'error':
                if isinstance(value, (list, dict)):
                    details.append(f"{key.replace('_', ' ').title()}: {len(value)} items")
                else:
                    details.append(f"{key.replace('_', ' ').title()}: {value}")
        
        if 'error' in status_data:
            details.append(f"Error: {status_data['error']}")
            
        self.details_label.setText("\n".join(details))

class ConnectionTable(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(3)
        self.setHorizontalHeaderLabels(['Local Address', 'Remote Address', 'Timestamp'])
        self.horizontalHeader().setStretchLastSection(True)
        
    def update_connections(self, connections):
        self.setRowCount(len(connections))
        for i, conn in enumerate(connections):
            self.setItem(i, 0, QTableWidgetItem(conn['local']))
            self.setItem(i, 1, QTableWidgetItem(conn['remote']))
            self.setItem(i, 2, QTableWidgetItem(conn['timestamp']))

class DriverTable(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(3)
        self.setHorizontalHeaderLabels(['Name', 'Path', 'State'])
        self.horizontalHeader().setStretchLastSection(True)
        
    def update_drivers(self, drivers):
        self.setRowCount(len(drivers))
        for i, driver in enumerate(drivers):
            self.setItem(i, 0, QTableWidgetItem(driver['Name']))
            self.setItem(i, 1, QTableWidgetItem(driver['Path']))
            self.setItem(i, 2, QTableWidgetItem(driver['State']))

class SystemMetricsFrame(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setStyleSheet("""
            QFrame {
                background-color: #2d2d2d;
                border-radius: 10px;
                padding: 10px;
            }
            QLabel {
                color: #ffffff;
                font-size: 12px;
            }
            QProgressBar {
                border: 1px solid #3d3d3d;
                border-radius: 5px;
                text-align: center;
                background-color: #1d1d1d;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 4px;
            }
        """)
        
        layout = QVBoxLayout()
        
        # CPU Usage
        self.cpu_label = QLabel("CPU Usage: 0%")
        self.cpu_bar = QProgressBar()
        self.cpu_bar.setMaximum(100)
        layout.addWidget(self.cpu_label)
        layout.addWidget(self.cpu_bar)
        
        # Memory Usage
        self.memory_label = QLabel("Memory Usage: 0%")
        self.memory_bar = QProgressBar()
        self.memory_bar.setMaximum(100)
        layout.addWidget(self.memory_label)
        layout.addWidget(self.memory_bar)
        
        # Disk Usage
        self.disk_label = QLabel("Disk Usage: 0%")
        self.disk_bar = QProgressBar()
        self.disk_bar.setMaximum(100)
        layout.addWidget(self.disk_label)
        layout.addWidget(self.disk_bar)
        
        # Network I/O
        self.network_label = QLabel("Network I/O: 0 B/s")
        layout.addWidget(self.network_label)
        
        # Uptime
        self.uptime_label = QLabel("Uptime: 0:00:00")
        layout.addWidget(self.uptime_label)
        
        self.setLayout(layout)
    
    def update_metrics(self, metrics):
        if not metrics:
            return
            
        # Update CPU
        cpu_usage = metrics.get('cpu_usage', 0)
        self.cpu_label.setText(f"CPU Usage: {cpu_usage}%")
        self.cpu_bar.setValue(int(cpu_usage))
        
        # Update Memory
        memory_usage = metrics.get('memory_usage', 0)
        self.memory_label.setText(f"Memory Usage: {memory_usage}%")
        self.memory_bar.setValue(int(memory_usage))
        
        # Update Disk
        disk_usage = metrics.get('disk_usage', 0)
        self.disk_label.setText(f"Disk Usage: {disk_usage}%")
        self.disk_bar.setValue(int(disk_usage))
        
        # Update Network
        net_io = metrics.get('network_io', {})
        bytes_sent = net_io.get('bytes_sent', 0)
        bytes_recv = net_io.get('bytes_recv', 0)
        self.network_label.setText(f"Network I/O: ↑{self._format_bytes(bytes_sent)}/s ↓{self._format_bytes(bytes_recv)}/s")
        
        # Update Uptime
        uptime = metrics.get('uptime', '0:00:00')
        self.uptime_label.setText(f"Uptime: {uptime}")
    
    def _format_bytes(self, bytes):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024:
                return f"{bytes:.1f}{unit}"
            bytes /= 1024
        return f"{bytes:.1f}TB"

class PCIDevicesFrame(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("pci_frame")
        self.setStyleSheet("""
            QFrame#pci_frame {
                background-color: #2b2b2b;
                border-radius: 10px;
                padding: 20px;
            }
            QLabel {
                color: white;
                font-size: 16px;
                margin-bottom: 10px;
            }
            QTableWidget {
                background-color: #363636;
                border: none;
                border-radius: 5px;
                color: white;
                gridline-color: #404040;
                font-size: 12px;
            }
            QTableWidget::item {
                padding: 8px;
                border: none;
            }
            QTableWidget::item:selected {
                background-color: #404040;
            }
            QHeaderView::section {
                background-color: #2b2b2b;
                color: white;
                padding: 8px;
                border: none;
                font-weight: bold;
                font-size: 13px;
            }
            QTableWidget::item:alternate {
                background-color: #323232;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        # Title
        title = QLabel("PCI Device Monitoring")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 15px;")
        layout.addWidget(title)

        # Status label
        self.status_label = QLabel()
        self.status_label.setStyleSheet("font-size: 14px; margin-bottom: 15px;")
        layout.addWidget(self.status_label)

        # Error label
        self.error_label = QLabel()
        self.error_label.setStyleSheet("color: #ff6b6b; font-size: 14px; margin-bottom: 15px;")
        self.error_label.hide()
        layout.addWidget(self.error_label)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "Device Name", 
            "Device ID", 
            "Manufacturer", 
            "Status", 
            "Suspicious Reasons"
        ])
        
        # Set column widths
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)  # Device Name
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)    # Device ID
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)    # Manufacturer
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)    # Status
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)  # Suspicious Reasons
        
        self.table.setColumnWidth(1, 200)  # Device ID
        self.table.setColumnWidth(2, 150)  # Manufacturer
        self.table.setColumnWidth(3, 80)   # Status

        # Table properties
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setShowGrid(True)
        self.table.setWordWrap(True)
        
        # Set row height
        self.table.verticalHeader().setDefaultSectionSize(40)
        self.table.verticalHeader().setVisible(False)
        
        # Enable sorting
        self.table.setSortingEnabled(True)
        
        # Set minimum size
        self.table.setMinimumHeight(400)
        
        layout.addWidget(self.table)

        # Refresh button
        refresh_button = QPushButton("Refresh")
        refresh_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
                font-size: 14px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        layout.addWidget(refresh_button, alignment=Qt.AlignmentFlag.AlignCenter)

    def update_status(self, status_data):
        try:
            if 'error' in status_data:
                self.status_label.setText("Status: Error")
                self.status_label.setStyleSheet("color: #ff6b6b; font-size: 14px;")
                self.error_label.setText(f"Error: {status_data['error']}")
                self.error_label.show()
                return

            # Update status label
            status = status_data.get('status', 'Unknown')
            count = status_data.get('count', 0)
            self.status_label.setText(f"Status: {status} ({count} suspicious devices found)")
            
            # Set status label color
            if status == 'OK':
                self.status_label.setStyleSheet("color: #4CAF50; font-size: 14px;")
            elif status == 'Warning':
                self.status_label.setStyleSheet("color: #FFA500; font-size: 14px;")
            else:
                self.status_label.setStyleSheet("color: white; font-size: 14px;")

            # Hide error label if no error
            self.error_label.hide()

            # Update table
            suspicious_devices = status_data.get('suspicious_devices', [])
            self.table.setRowCount(len(suspicious_devices))
            
            for row, device in enumerate(suspicious_devices):
                # Device Name
                name_item = QTableWidgetItem(device.get('name', 'Unknown'))
                name_item.setToolTip(device.get('name', 'Unknown'))
                self.table.setItem(row, 0, name_item)
                
                # Device ID
                device_id = device.get('device_id', 'Unknown')
                id_item = QTableWidgetItem(device_id)
                id_item.setToolTip(device_id)
                self.table.setItem(row, 1, id_item)
                
                # Manufacturer
                manufacturer = device.get('manufacturer', 'Unknown')
                manufacturer_item = QTableWidgetItem(manufacturer)
                manufacturer_item.setToolTip(manufacturer)
                self.table.setItem(row, 2, manufacturer_item)
                
                # Status
                status_item = QTableWidgetItem(device.get('status', 'Unknown'))
                if device.get('status') == 'OK':
                    status_item.setForeground(QColor('#4CAF50'))
                else:
                    status_item.setForeground(QColor('#FFA500'))
                self.table.setItem(row, 3, status_item)
                
                # Suspicious Reasons
                reasons = device.get('suspicious_reasons', [])
                reasons_text = '\n'.join(reasons) if reasons else 'None'
                reasons_item = QTableWidgetItem(reasons_text)
                reasons_item.setToolTip(reasons_text)
                self.table.setItem(row, 4, reasons_item)

            # Resize rows to content
            self.table.resizeRowsToContents()

        except Exception as e:
            self.status_label.setText("Status: Error")
            self.status_label.setStyleSheet("color: #ff6b6b; font-size: 14px;")
            self.error_label.setText(f"Error updating PCI devices table: {str(e)}")
            self.error_label.show()

class MemoryIntegrityFrame(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)

        # Status indicator
        self.status_label = QLabel("Status: Initializing...")
        self.status_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        layout.addWidget(self.status_label)

        # Memory metrics
        metrics_group = QGroupBox("Memory Metrics")
        metrics_layout = QGridLayout()
        metrics_group.setLayout(metrics_layout)

        self.metrics_labels = {}
        metrics = ['Available', 'Cache', 'Committed', 'NonPagedPool', 'PagedPool']
        for i, metric in enumerate(metrics):
            label = QLabel(f"{metric}:")
            value = QLabel("0")
            self.metrics_labels[metric] = value
            metrics_layout.addWidget(label, i, 0)
            metrics_layout.addWidget(value, i, 1)

        layout.addWidget(metrics_group)

        # Memory access table
        access_group = QGroupBox("Memory Access Monitoring")
        access_layout = QVBoxLayout()
        access_group.setLayout(access_layout)

        self.access_table = QTableWidget()
        self.access_table.setColumnCount(6)
        self.access_table.setHorizontalHeaderLabels(['Process', 'PID', 'Working Set', 'Private Memory', 'Virtual Memory', 'Timestamp'])
        self.access_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.access_table.setMinimumHeight(200)
        access_layout.addWidget(self.access_table)

        layout.addWidget(access_group)

        # Anomalies table
        anomalies_group = QGroupBox("Detected Anomalies")
        anomalies_layout = QVBoxLayout()
        anomalies_group.setLayout(anomalies_layout)

        self.anomalies_table = QTableWidget()
        self.anomalies_table.setColumnCount(4)
        self.anomalies_table.setHorizontalHeaderLabels(['Type', 'Process', 'Value', 'Timestamp'])
        self.anomalies_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.anomalies_table.setMinimumHeight(150)
        anomalies_layout.addWidget(self.anomalies_table)

        layout.addWidget(anomalies_group)

        # Integrity checks
        integrity_group = QGroupBox("Integrity Checks")
        integrity_layout = QVBoxLayout()
        integrity_group.setLayout(integrity_layout)

        self.integrity_table = QTableWidget()
        self.integrity_table.setColumnCount(4)
        self.integrity_table.setHorizontalHeaderLabels(['Kernel Memory', 'Page Faults', 'Cache Faults', 'Timestamp'])
        self.integrity_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.integrity_table.setMinimumHeight(150)
        integrity_layout.addWidget(self.integrity_table)

        layout.addWidget(integrity_group)

    def update_status(self, status_data):
        """Update the memory integrity display with new data"""
        try:
            if not isinstance(status_data, dict):
                print(f"Invalid status data type: {type(status_data)}")
                return

            # Update status
            status = status_data.get('status', 'Unknown')
            self.status_label.setText(f"Status: {status}")
            status_color = {
                'OK': 'green',
                'Warning': 'orange',
                'Error': 'red',
                'Monitoring': 'blue'
            }.get(status, 'gray')
            self.status_label.setStyleSheet(f"color: {status_color}; font-size: 14px; font-weight: bold;")

            # Update metrics
            metrics = status_data.get('metrics', {})
            if isinstance(metrics, dict):
                for metric, value in metrics.items():
                    if metric in self.metrics_labels:
                        self.metrics_labels[metric].setText(f"{value:,} bytes")

            # Update memory access table
            self.access_table.setRowCount(0)
            memory_access = status_data.get('memory_access', [])
            if isinstance(memory_access, list):
                for access in memory_access:
                    if isinstance(access, dict):
                        row = self.access_table.rowCount()
                        self.access_table.insertRow(row)
                        self.access_table.setItem(row, 0, QTableWidgetItem(access.get('process', 'Unknown')))
                        self.access_table.setItem(row, 1, QTableWidgetItem(str(access.get('pid', 0))))
                        self.access_table.setItem(row, 2, QTableWidgetItem(f"{access.get('working_set', 0):,} bytes"))
                        self.access_table.setItem(row, 3, QTableWidgetItem(f"{access.get('private_memory', 0):,} bytes"))
                        self.access_table.setItem(row, 4, QTableWidgetItem(f"{access.get('virtual_memory', 0):,} bytes"))
                        self.access_table.setItem(row, 5, QTableWidgetItem(access.get('timestamp', '')))

            # Update anomalies table
            self.anomalies_table.setRowCount(0)
            anomalies = status_data.get('anomalies', [])
            if isinstance(anomalies, list):
                for anomaly in anomalies:
                    if isinstance(anomaly, dict):
                        row = self.anomalies_table.rowCount()
                        self.anomalies_table.insertRow(row)
                        self.anomalies_table.setItem(row, 0, QTableWidgetItem(anomaly.get('type', 'Unknown')))
                        self.anomalies_table.setItem(row, 1, QTableWidgetItem(anomaly.get('process', 'N/A')))
                        self.anomalies_table.setItem(row, 2, QTableWidgetItem(str(anomaly.get('value', 'N/A'))))
                        self.anomalies_table.setItem(row, 3, QTableWidgetItem(anomaly.get('timestamp', '')))

            # Update integrity checks table
            self.integrity_table.setRowCount(0)
            integrity_checks = status_data.get('integrity_checks', [])
            if isinstance(integrity_checks, list):
                for check in integrity_checks:
                    if isinstance(check, dict):
                        row = self.integrity_table.rowCount()
                        self.integrity_table.insertRow(row)
                        self.integrity_table.setItem(row, 0, QTableWidgetItem(f"{check.get('kernel_memory', 0):,} bytes"))
                        self.integrity_table.setItem(row, 1, QTableWidgetItem(f"{check.get('page_faults', 0):,}"))
                        self.integrity_table.setItem(row, 2, QTableWidgetItem(f"{check.get('cache_faults', 0):,}"))
                        self.integrity_table.setItem(row, 3, QTableWidgetItem(check.get('timestamp', '')))

        except Exception as e:
            print(f"Error updating memory integrity display: {e}")
            self.status_label.setText(f"Status: Error - {str(e)}")
            self.status_label.setStyleSheet("color: red; font-size: 14px; font-weight: bold;")

class SystemResourcesFrame(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Status Label
        self.status_label = QLabel("Status: Initializing...")
        self.status_label.setStyleSheet("color: #FFA500; font-size: 14px;")
        layout.addWidget(self.status_label)

        # CPU Usage
        cpu_group = QGroupBox("CPU Usage")
        cpu_layout = QVBoxLayout()
        self.cpu_label = QLabel("CPU: 0%")
        self.cpu_label.setStyleSheet("font-size: 12px;")
        cpu_layout.addWidget(self.cpu_label)
        cpu_group.setLayout(cpu_layout)
        layout.addWidget(cpu_group)

        # Memory Usage
        memory_group = QGroupBox("Memory Usage")
        memory_layout = QVBoxLayout()
        self.memory_label = QLabel("Memory: 0%")
        self.memory_label.setStyleSheet("font-size: 12px;")
        memory_layout.addWidget(self.memory_label)
        memory_group.setLayout(memory_layout)
        layout.addWidget(memory_group)

        # Disk Usage
        disk_group = QGroupBox("Disk Usage")
        disk_layout = QVBoxLayout()
        self.disk_label = QLabel("Disk: 0%")
        self.disk_label.setStyleSheet("font-size: 12px;")
        disk_layout.addWidget(self.disk_label)
        disk_group.setLayout(disk_layout)
        layout.addWidget(disk_group)

        # Network I/O
        network_group = QGroupBox("Network I/O")
        network_layout = QVBoxLayout()
        self.network_label = QLabel("Network: 0 B/s")
        self.network_label.setStyleSheet("font-size: 12px;")
        network_layout.addWidget(self.network_label)
        network_group.setLayout(network_layout)
        layout.addWidget(network_group)

        # System Uptime
        uptime_group = QGroupBox("System Uptime")
        uptime_layout = QVBoxLayout()
        self.uptime_label = QLabel("Uptime: 0:00:00")
        self.uptime_label.setStyleSheet("font-size: 12px;")
        uptime_layout.addWidget(self.uptime_label)
        uptime_group.setLayout(uptime_layout)
        layout.addWidget(uptime_group)

        # Add stretch to push everything to the top
        layout.addStretch()

    def update_status(self, status_data):
        try:
            if not isinstance(status_data, dict):
                self.status_label.setText("Status: Error - Invalid data format")
                self.status_label.setStyleSheet("color: #FF0000; font-size: 14px;")
                return

            # Update CPU usage
            cpu_usage = status_data.get('cpu_usage', 0)
            self.cpu_label.setText(f"CPU: {cpu_usage}%")
            self.cpu_label.setStyleSheet(f"font-size: 12px; color: {'#FF0000' if cpu_usage > 80 else '#00FF00'};")

            # Update memory usage
            memory_usage = status_data.get('memory_usage', 0)
            self.memory_label.setText(f"Memory: {memory_usage}%")
            self.memory_label.setStyleSheet(f"font-size: 12px; color: {'#FF0000' if memory_usage > 80 else '#00FF00'};")

            # Update disk usage
            disk_usage = status_data.get('disk_usage', 0)
            self.disk_label.setText(f"Disk: {disk_usage}%")
            self.disk_label.setStyleSheet(f"font-size: 12px; color: {'#FF0000' if disk_usage > 80 else '#00FF00'};")

            # Update network I/O
            network_io = status_data.get('network_io', {})
            bytes_sent = network_io.get('bytes_sent', 0)
            bytes_recv = network_io.get('bytes_recv', 0)
            self.network_label.setText(f"Network: ↑{self._format_bytes(bytes_sent)}/s ↓{self._format_bytes(bytes_recv)}/s")

            # Update uptime
            uptime = status_data.get('uptime', '0:00:00')
            self.uptime_label.setText(f"Uptime: {uptime}")

            # Update status
            self.status_label.setText("Status: Monitoring")
            self.status_label.setStyleSheet("color: #00FF00; font-size: 14px;")

        except Exception as e:
            self.status_label.setText(f"Status: Error - {str(e)}")
            self.status_label.setStyleSheet("color: #FF0000; font-size: 14px;")

    def _format_bytes(self, bytes_value):
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024:
                return f"{bytes_value:.1f}{unit}"
            bytes_value /= 1024
        return f"{bytes_value:.1f}TB"

class OverviewFrame(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        # IOMMU Status
        self.iommu_frame = StatusFrame("IOMMU Status")
        layout.addWidget(self.iommu_frame)

        # TPM Status
        self.tpm_frame = StatusFrame("TPM Status")
        layout.addWidget(self.tpm_frame)

        # Secure Boot Status
        self.secure_boot_frame = StatusFrame("Secure Boot Status")
        layout.addWidget(self.secure_boot_frame)

        # Boot Status
        self.boot_status_frame = StatusFrame("Boot Status")
        layout.addWidget(self.boot_status_frame)

        # Add stretch to push everything to the top
        layout.addStretch()

    def update_iommu_status(self, status_data):
        self.iommu_frame.update_status(status_data)

    def update_tpm_status(self, status_data):
        self.tpm_frame.update_status(status_data)

    def update_secure_boot_status(self, status_data):
        self.secure_boot_frame.update_status(status_data)

    def update_boot_status(self, status_data):
        self.boot_status_frame.update_status(status_data)

class NetworkFrame(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Status Label
        self.status_label = QLabel("Status: Initializing...")
        self.status_label.setStyleSheet("color: #FFA500; font-size: 14px;")
        layout.addWidget(self.status_label)

        # Connections Table
        self.connections_table = QTableWidget()
        self.connections_table.setColumnCount(4)
        self.connections_table.setHorizontalHeaderLabels(['Local Address', 'Remote Address', 'State', 'Process'])
        self.connections_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.connections_table)

    def update_status(self, status_data):
        try:
            if not isinstance(status_data, dict):
                self.status_label.setText("Status: Error - Invalid data format")
                self.status_label.setStyleSheet("color: #FF0000; font-size: 14px;")
                return

            connections = status_data.get('new_connections', [])
            self.connections_table.setRowCount(len(connections))
            
            for row, conn in enumerate(connections):
                self.connections_table.setItem(row, 0, QTableWidgetItem(conn.get('local_address', '')))
                self.connections_table.setItem(row, 1, QTableWidgetItem(conn.get('remote_address', '')))
                self.connections_table.setItem(row, 2, QTableWidgetItem(conn.get('state', '')))
                self.connections_table.setItem(row, 3, QTableWidgetItem(conn.get('process_name', '')))

            self.status_label.setText("Status: Monitoring")
            self.status_label.setStyleSheet("color: #00FF00; font-size: 14px;")

        except Exception as e:
            self.status_label.setText(f"Status: Error - {str(e)}")
            self.status_label.setStyleSheet("color: #FF0000; font-size: 14px;")

class DriversFrame(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Status Label
        self.status_label = QLabel("Status: Initializing...")
        self.status_label.setStyleSheet("color: #FFA500; font-size: 14px;")
        layout.addWidget(self.status_label)

        # Drivers Table
        self.drivers_table = QTableWidget()
        self.drivers_table.setColumnCount(5)
        self.drivers_table.setHorizontalHeaderLabels(['Name', 'Path', 'State', 'Vendor', 'Status'])
        self.drivers_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.drivers_table)

        # Add stretch to push everything to the top
        layout.addStretch()

    def update_status(self, status_data):
        try:
            if not isinstance(status_data, dict):
                self.status_label.setText("Status: Error - Invalid data format")
                self.status_label.setStyleSheet("color: #FF0000; font-size: 14px;")
                return

            drivers = status_data.get('unsigned_drivers', [])
            self.drivers_table.setRowCount(len(drivers))
            
            for row, driver in enumerate(drivers):
                # Set driver name
                name_item = QTableWidgetItem(driver.get('Name', 'Unknown'))
                self.drivers_table.setItem(row, 0, name_item)
                
                # Set driver path
                path_item = QTableWidgetItem(driver.get('Path', 'Unknown'))
                self.drivers_table.setItem(row, 1, path_item)
                
                # Set driver state
                state_item = QTableWidgetItem(driver.get('State', 'Unknown'))
                self.drivers_table.setItem(row, 2, state_item)
                
                # Set vendor
                vendor_item = QTableWidgetItem(driver.get('Vendor', 'Unknown'))
                self.drivers_table.setItem(row, 3, vendor_item)
                
                # Set status with color coding
                status_item = QTableWidgetItem(driver.get('Status', 'Unknown'))
                if driver.get('Status') == 'Signed':
                    status_item.setForeground(QColor('#00FF00'))  # Green for signed
                else:
                    status_item.setForeground(QColor('#FF0000'))  # Red for unsigned
                self.drivers_table.setItem(row, 4, status_item)

            # Update status label
            if drivers:
                self.status_label.setText(f"Status: Found {len(drivers)} unsigned drivers")
                self.status_label.setStyleSheet("color: #FF0000; font-size: 14px;")
            else:
                self.status_label.setText("Status: No unsigned drivers found")
                self.status_label.setStyleSheet("color: #00FF00; font-size: 14px;")

        except Exception as e:
            self.status_label.setText(f"Status: Error - {str(e)}")
            self.status_label.setStyleSheet("color: #FF0000; font-size: 14px;")

class PCIFrame(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Status Label
        self.status_label = QLabel("Status: Initializing...")
        self.status_label.setStyleSheet("color: #FFA500; font-size: 14px;")
        layout.addWidget(self.status_label)

        # PCI Devices Table
        self.pci_table = QTableWidget()
        self.pci_table.setColumnCount(5)
        self.pci_table.setHorizontalHeaderLabels(['Device Name', 'Device ID', 'Manufacturer', 'Status', 'Suspicious Reasons'])
        self.pci_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.pci_table)

    def update_status(self, status_data):
        try:
            if not isinstance(status_data, dict):
                self.status_label.setText("Status: Error - Invalid data format")
                self.status_label.setStyleSheet("color: #FF0000; font-size: 14px;")
                return

            devices = status_data.get('suspicious_devices', [])
            self.pci_table.setRowCount(len(devices))
            
            for row, device in enumerate(devices):
                self.pci_table.setItem(row, 0, QTableWidgetItem(device.get('name', '')))
                self.pci_table.setItem(row, 1, QTableWidgetItem(device.get('device_id', '')))
                self.pci_table.setItem(row, 2, QTableWidgetItem(device.get('manufacturer', '')))
                self.pci_table.setItem(row, 3, QTableWidgetItem(device.get('status', '')))
                reasons = device.get('suspicious_reasons', [])
                self.pci_table.setItem(row, 4, QTableWidgetItem('\n'.join(reasons)))

            self.status_label.setText("Status: Monitoring")
            self.status_label.setStyleSheet("color: #00FF00; font-size: 14px;")

        except Exception as e:
            self.status_label.setText(f"Status: Error - {str(e)}")
            self.status_label.setStyleSheet("color: #FF0000; font-size: 14px;")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Hardware Security Monitor")
        self.setMinimumSize(1200, 800)
        
        # Set dark theme
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QLabel {
                color: #ffffff;
            }
            QScrollArea {
                background-color: #1e1e1e;
                border: none;
            }
            QTabWidget::pane {
                border: 1px solid #2d2d2d;
                background-color: #1e1e1e;
            }
            QTabBar::tab {
                background-color: #2d2d2d;
                color: #ffffff;
                padding: 8px 16px;
                border: 1px solid #2d2d2d;
            }
            QTabBar::tab:selected {
                background-color: #3d3d3d;
            }
            QGroupBox {
                border: 1px solid #2d2d2d;
                margin-top: 10px;
                padding-top: 10px;
                color: #ffffff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px;
            }
            QTableWidget {
                background-color: #2d2d2d;
                color: #ffffff;
                gridline-color: #3d3d3d;
            }
            QHeaderView::section {
                background-color: #2d2d2d;
                color: #ffffff;
                padding: 4px;
                border: 1px solid #3d3d3d;
            }
            QPushButton {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #3d3d3d;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #3d3d3d;
            }
            QPushButton#pause_button {
                background-color: #d32f2f;
                color: white;
            }
            QPushButton#pause_button[paused=true] {
                background-color: #4CAF50;
            }
        """)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create scroll area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        layout.addWidget(scroll_area)
        
        # Create content widget
        content_widget = QWidget()
        scroll_area.setWidget(content_widget)
        content_layout = QVBoxLayout(content_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        content_layout.addWidget(self.tab_widget)
        
        # Create frames for each tab
        self.overview_frame = OverviewFrame()
        self.network_frame = NetworkFrame()
        self.drivers_frame = DriversFrame()
        self.pci_frame = PCIFrame()
        self.memory_frame = MemoryIntegrityFrame()
        self.system_resources_frame = SystemResourcesFrame()
        
        # Add tabs
        self.tab_widget.addTab(self.overview_frame, "Overview")
        self.tab_widget.addTab(self.network_frame, "Network Connections")
        self.tab_widget.addTab(self.drivers_frame, "Drivers")
        self.tab_widget.addTab(self.pci_frame, "PCI Devices")
        self.tab_widget.addTab(self.memory_frame, "Memory Integrity")
        self.tab_widget.addTab(self.system_resources_frame, "System Resources")
        
        # Create button layout
        button_layout = QHBoxLayout()
        
        # Add refresh button
        self.refresh_button = QPushButton("Refresh Status")
        self.refresh_button.clicked.connect(self.refresh_status)
        button_layout.addWidget(self.refresh_button)
        
        # Add pause/resume button
        self.pause_button = QPushButton("Pause Auto-Refresh")
        self.pause_button.setObjectName("pause_button")
        self.pause_button.setProperty("paused", False)
        self.pause_button.clicked.connect(self.toggle_auto_refresh)
        button_layout.addWidget(self.pause_button)
        
        # Add button layout to main layout
        content_layout.addLayout(button_layout)
        
        # Add status label
        self.refresh_status_label = QLabel("Auto-refresh: Active")
        self.refresh_status_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        content_layout.addWidget(self.refresh_status_label)
        
        # Initialize hardware detector
        self.hardware_detector = HardwareDetector()
        
        # Start status update thread
        self.status_update_thread = StatusUpdateThread(self.hardware_detector)
        self.status_update_thread.status_updated.connect(self.update_status)
        self.status_update_thread.start()

    def toggle_auto_refresh(self):
        """Toggle automatic refresh on/off"""
        if self.status_update_thread.is_paused():
            self.status_update_thread.resume()
            self.pause_button.setText("Pause Auto-Refresh")
            self.pause_button.setProperty("paused", False)
            self.refresh_status_label.setText("Auto-refresh: Active")
        else:
            self.status_update_thread.pause()
            self.pause_button.setText("Resume Auto-Refresh")
            self.pause_button.setProperty("paused", True)
            self.refresh_status_label.setText("Auto-refresh: Paused")
        
        # Force style refresh
        self.pause_button.style().unpolish(self.pause_button)
        self.pause_button.style().polish(self.pause_button)
        
        # Immediately refresh to show current status
        self.refresh_status()

    def update_status(self, status_data):
        """Update all frames with new status data"""
        try:
            if not isinstance(status_data, dict):
                print("Error: Invalid status data format")
                return
                
            # Check for critical security errors first
            if 'status' in status_data and status_data['status'] == 'Critical Security Error':
                self._show_critical_security_error(status_data)
                return

            # Update overview frame
            if 'iommu' in status_data:
                self.overview_frame.update_iommu_status(status_data['iommu'])
            if 'tpm' in status_data:
                self.overview_frame.update_tpm_status(status_data['tpm'])
            if 'secure_boot' in status_data:
                self.overview_frame.update_secure_boot_status(status_data['secure_boot'])
            if 'boot_status' in status_data:
                self.overview_frame.update_boot_status(status_data['boot_status'])

            # Update network frame
            if 'connections' in status_data:
                self.network_frame.update_status(status_data['connections'])

            # Update drivers frame
            if 'unsigned_drivers' in status_data:
                self.drivers_frame.update_status(status_data['unsigned_drivers'])

            # Update PCI frame
            if 'pci_devices' in status_data:
                self.pci_frame.update_status(status_data['pci_devices'])

            # Update memory frame
            if 'memory_integrity' in status_data:
                self.memory_frame.update_status(status_data['memory_integrity'])

            # Update system resources frame
            if 'system_metrics' in status_data:
                self.system_resources_frame.update_status(status_data['system_metrics'])
                
            # Check for debugger info
            if 'debugger' in status_data:
                self._handle_debugger_status(status_data['debugger'])

        except Exception as e:
            print(f"Error updating status: {str(e)}")
            
    def _show_critical_security_error(self, status_data):
        """Display a critical security error dialog"""
        from PyQt6.QtWidgets import QMessageBox
        
        error_msg = status_data.get('error', 'Unknown critical security error')
        
        # Create error dialog
        error_dialog = QMessageBox(self)
        error_dialog.setIcon(QMessageBox.Icon.Critical)
        error_dialog.setWindowTitle("ALARM!!!!!")
        error_dialog.setText("Debugger Detected")
        error_dialog.setInformativeText(error_msg)
        error_dialog.setDetailedText(
            "This application has detected a security violation that prevents it from running.\n\n"
            "Possible reasons include:\n"
            "- A debugger is attached to the application\n"
            "- Reverse engineering tools are active\n"
            "- Security monitoring has been compromised\n\n"
            "The application will now close for security reasons."
        )
        error_dialog.setStandardButtons(QMessageBox.StandardButton.Close)
        error_dialog.setDefaultButton(QMessageBox.StandardButton.Close)
        
        # Apply custom styling to make it stand out
        error_dialog.setStyleSheet("""
            QMessageBox {
                background-color: #300;
                color: white;
            }
            QLabel {
                color: white;
            }
            QPushButton {
                background-color: #700;
                color: white;
                border: 1px solid #900;
                padding: 5px 15px;
            }
            QPushButton:hover {
                background-color: #900;
            }
        """)
        
        # Show the dialog and quit on close
        result = error_dialog.exec()
        self.close()  # Close the main window
        
    def _handle_debugger_status(self, debugger_data):
        """Handle debugger status information"""
        if debugger_data.get('status') == 'Warning':
            # Create a status label or show an alert
            from PyQt6.QtWidgets import QMessageBox
            
            debug_dialog = QMessageBox(self)
            debug_dialog.setIcon(QMessageBox.Icon.Warning)
            debug_dialog.setWindowTitle("Debugger Warning")
            debug_dialog.setText("Debugger Detected")
            debug_dialog.setInformativeText(debugger_data.get('error', 'A debugger has been detected.'))
            
            detected_debuggers = debugger_data.get('detected_debuggers', [])
            if detected_debuggers:
                details = "Detected debugging tools:\n\n"
                for i, debugger in enumerate(detected_debuggers):
                    details += f"{i+1}. {debugger.get('name', 'Unknown')}\n"
                debug_dialog.setDetailedText(details)
            
            debug_dialog.setStandardButtons(QMessageBox.StandardButton.Ok)
            debug_dialog.exec()

    def refresh_status(self):
        """Manually trigger a status refresh"""
        status = self.hardware_detector.get_all_status()
        self.update_status(status)

    def closeEvent(self, event):
        """Clean up when window is closed"""
        self.status_update_thread.stop()
        self.status_update_thread.wait()
        event.accept()

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec()) 