import win32com.client
import win32security
import win32api
import win32con
import ctypes
from ctypes import wintypes
import os
import subprocess
from typing import Dict, Any, List
import time
import psutil
import win32process
import win32service
import win32serviceutil
import win32net
import win32netcon
import win32evtlog
import win32evtlogutil
import win32timezone
from datetime import datetime
import threading
from queue import Queue
import concurrent.futures
import json
import requests
from crypto_manager import CryptoManager

class HardwareDetector:
    def __init__(self):
        try:
            self.wmi = win32com.client.GetObject("winmgmts:")
            self.connection_history = set()
            self.connection_list = []  # List to store all connections
            self.boot_history = []
            self.unsigned_drivers = []
            self.status_queue = Queue()
            self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)
            self.wmi_lock = threading.Lock()  # Lock for WMI operations
            self.pci_devices = []  # List to store PCI device information
            self.system_metrics = {}  # Dictionary to store system health metrics
            self._trusted_vendors = None
            self._last_vendor_update = None
            self._vendor_update_lock = threading.Lock()
            self.crypto = CryptoManager()
            self.secure_log_file = "secure_hardware.log"
            self.secure_config_file = "secure_config.dat"
            self.initialize_secure_logging()
        except Exception as e:
            print(f"WMI initialization error: {e}")
            self.wmi = None

    def initialize_secure_logging(self):
        """Initialize secure logging system"""
        try:
            # Create initial secure log entry
            self.crypto.secure_log("Hardware Security Monitor initialized", self.secure_log_file)
            
            # Create default secure configuration
            default_config = {
                'monitoring_interval': 5,
                'alert_thresholds': {
                    'memory_usage': 90,
                    'cpu_usage': 80,
                    'network_connections': 100
                },
                'trusted_vendors': [
                    'Microsoft',
                    'Intel',
                    'AMD',
                    'NVIDIA'
                ]
            }
            self.crypto.secure_config(default_config, self.secure_config_file)
        except Exception as e:
            print(f"Error initializing secure logging: {e}")

    def _run_powershell_command(self, command: str, timeout: int = 5) -> Dict[str, Any]:
        """Run PowerShell command in background"""
        try:
            # Format the command properly
            if not command.endswith("ConvertTo-Json"):
                command = f"$result = {command}; if ($result) {{ $result | ConvertTo-Json -Depth 10 }} else {{ '{{}}' }}"
            
            # Add error handling to PowerShell command
            ps_command = f"""
            [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
            try {{
                {command}
            }} catch {{
                Write-Error $_.Exception.Message
                exit 1
            }}
            """
            
            # Run PowerShell with proper encoding
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            
            result = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=timeout,
                startupinfo=startupinfo
            )
            
            # Handle output
            if result.returncode == 0 and result.stdout.strip():
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError as e:
                    print(f"Invalid JSON output: {result.stdout}")
                    # Try to clean and parse the output
                    cleaned_output = result.stdout.strip()
                    # Remove TypeData error message that appears in the output
                    if "Error in TypeData" in cleaned_output:
                        cleaned_output = cleaned_output.split(']', 1)[-1].strip()
                    try:
                        return json.loads(cleaned_output)
                    except:
                        print(f"Failed to parse cleaned JSON: {e}")
                        return None
            
            # Handle error output
            if result.stderr:
                print(f"PowerShell error: {result.stderr}")
            
            return None
        except subprocess.TimeoutExpired:
            print(f"PowerShell command timed out after {timeout} seconds")
            return None
        except Exception as e:
            print(f"PowerShell command error: {e}")
            return None

    def _check_unsigned_drivers_async(self):
        """Check for unsigned drivers and DLLs in background"""
        try:
            # Use a more generic approach to find unsigned files
            result = self._run_powershell_command("""
            # Get driver info with signature verification
            $drivers = Get-WmiObject Win32_SystemDriver | 
                Where-Object { $_.State -eq 'Running' } |
                ForEach-Object {
                    $file = $_.PathName
                    if ($file -match '^\\\\\\\\.*') {
                        $file = $file -replace '^\\\\\\\\\\\\?\\\\', ''
                    }
                    
                    # Default to Unknown for signature status
                    $status = 'Unknown'
                    if (Test-Path -LiteralPath $file -ErrorAction SilentlyContinue) {
                        try {
                            $sig = Get-AuthenticodeSignature -FilePath $file -ErrorAction SilentlyContinue
                            if ($sig -and $sig.Status -eq 'Valid') {
                                $status = 'Signed'
                            } else {
                                $status = 'Unsigned'
                            }
                        } catch {
                            # Leave status as Unknown
                        }
                    }

                    @{
                        Name = $_.Name
                        PathName = $file
                        State = $_.State
                        StartMode = $_.StartMode
                        ServiceType = $_.ServiceType
                        Vendor = $_.Manufacturer
                        Status = $status
                    }
                }
            
            # Filter unsigned drivers
            $unsigned_items = $drivers | Where-Object { $_.Status -eq 'Unsigned' }
            $unsigned_items | ConvertTo-Json -Depth 5
            """, timeout=30)

            # If we get a result, process it
            if result:
                try:
                    # Handle both list and dict results
                    if isinstance(result, list):
                        filtered_items = result
                    elif isinstance(result, dict):
                        filtered_items = [result]
                    else:
                        filtered_items = []
                    
                    self.status_queue.put(('unsigned_drivers', {
                        'status': 'Warning' if filtered_items else 'OK',
                        'unsigned_drivers': filtered_items,
                        'total_count': len(filtered_items),
                        'driver_count': len(filtered_items)
                    }))
                except Exception as e:
                    print(f"Error processing unsigned drivers data: {e}")
                    self.status_queue.put(('unsigned_drivers', {
                        'status': 'Error',
                        'error': f"Error processing data: {e}"
                    }))
            else:
                self.status_queue.put(('unsigned_drivers', {
                    'status': 'OK',
                    'unsigned_drivers': [],
                    'total_count': 0,
                    'driver_count': 0
                }))

        except Exception as e:
            error_msg = f"Driver check error: {str(e)}"
            print(error_msg)
            self.crypto.secure_log(error_msg, self.secure_log_file)
            self.status_queue.put(('unsigned_drivers', {
                'status': 'Error',
                'error': str(e)
            }))

    def _check_connections_async(self):
        """Check connections in background"""
        try:
            current_connections = set()
            new_connections = []
            
            # Get current active connections
            for conn in psutil.net_connections():
                if conn.status == 'ESTABLISHED':
                    connection = f"{conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}"
                    current_connections.add(connection)
                    
                    # Add to connection list if not already present
                    if connection not in self.connection_list:
                        self.connection_list.append(connection)
                        new_connections.append({
                            'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'timestamp': datetime.now().isoformat()
                        })

            # Update connection history with active connections
            self.connection_history = current_connections

            # Keep only the last 100 connections in the list
            if len(self.connection_list) > 100:
                self.connection_list = self.connection_list[-100:]

            # Create a list of active connections with their status
            active_connections = []
            for conn in self.connection_list:
                is_active = conn in current_connections
                active_connections.append({
                    'connection': conn,
                    'active': is_active,
                    'timestamp': datetime.now().isoformat() if is_active else None
                })

            self.status_queue.put(('connections', {
                'status': 'Monitoring',
                'active_connections': len(current_connections),
                'new_connections': new_connections,
                'all_connections': active_connections  # Include all connections with their active status
            }))
        except Exception as e:
            self.status_queue.put(('connections', {'status': 'Error', 'error': str(e)}))

    def _check_boot_status_async(self):
        """Check boot status in background"""
        try:
            boot_status = {
                'secure_boot': False,
                'boot_integrity': False,
                'boot_measurements': [],
                'last_boot_time': None,
                'boot_mode': 'Unknown',
                'boot_device': 'Unknown',
                'firmware_type': 'Unknown',
                'boot_status': 'Unknown'
            }

            # Get comprehensive system boot information
            try:
                result = self._run_powershell_command("""
                $computerInfo = Get-ComputerInfo
                $secureBoot = Confirm-SecureBootUEFI
                $tpm = Get-Tpm
                $bitlocker = Get-BitLockerVolume -MountPoint $env:SystemDrive
                $bootPartition = Get-Partition | Where-Object { $_.IsBoot -eq $true }
                
                @{
                    FirmwareType = $computerInfo.BiosFirmwareType
                    SecureBoot = $secureBoot
                    UEFISecureBootEnabled = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State' -ErrorAction SilentlyContinue).UEFISecureBootEnabled
                    BootMode = if ($computerInfo.BiosFirmwareType -eq 'Uefi') { 'UEFI' } else { 'Legacy' }
                    BootDevice = $computerInfo.OsBootDevice
                    SystemPartition = $env:SystemDrive
                    BootPartition = if ($bootPartition) { $bootPartition.DriveLetter } else { $null }
                    OsVersion = $computerInfo.OsVersion
                    OsArchitecture = $computerInfo.OsArchitecture
                    BiosManufacturer = $computerInfo.BiosManufacturer
                    BiosVersion = $computerInfo.BiosVersion
                    TpmPresent = $tpm.TpmPresent
                    TpmEnabled = $tpm.TpmEnabled
                    TpmReady = $tpm.TpmReady
                    BitLockerProtection = if ($bitlocker) { $bitlocker.ProtectionStatus } else { 'Off' }
                    BitLockerEncryption = if ($bitlocker) { $bitlocker.EncryptionMethod } else { 'None' }
                    BootStatus = $computerInfo.CsBootupState
                } | ConvertTo-Json""")

                if result and isinstance(result, dict):
                    # Update boot status with comprehensive information
                    boot_status.update({
                        'firmware_type': str(result.get('FirmwareType', 'Unknown')),
                        'secure_boot': bool(result.get('SecureBoot', False)) or bool(result.get('UEFISecureBootEnabled', False)),
                        'boot_mode': str(result.get('BootMode', 'Unknown')),
                        'boot_device': str(result.get('BootDevice', 'Unknown')),
                        'system_partition': str(result.get('SystemPartition', 'Unknown')),
                        'boot_partition': str(result.get('BootPartition', 'Unknown')),
                        'os_version': str(result.get('OsVersion', 'Unknown')),
                        'os_architecture': str(result.get('OsArchitecture', 'Unknown')),
                        'bios_manufacturer': str(result.get('BiosManufacturer', 'Unknown')),
                        'bios_version': str(result.get('BiosVersion', 'Unknown')),
                        'boot_status': str(result.get('BootStatus', 'Unknown'))  # Use actual boot status from system
                    })

                    # Set boot integrity based on TPM status
                    if all([
                        result.get('TpmPresent', False),
                        result.get('TpmEnabled', False),
                        result.get('TpmReady', False)
                    ]):
                        boot_status['boot_integrity'] = True

                    # Add BitLocker information
                    boot_status['bitlocker_status'] = {
                        'protection': str(result.get('BitLockerProtection', 'Unknown')),
                        'encryption': str(result.get('BitLockerEncryption', 'Unknown'))
                    }

            except Exception as e:
                print(f"System info check error: {e}")

            # Get boot time
            try:
                boot_time = datetime.fromtimestamp(psutil.boot_time())
                boot_status['last_boot_time'] = boot_time.isoformat()

                # Update boot history
                if boot_time not in self.boot_history:
                    self.boot_history.append(boot_time)
                    if len(self.boot_history) > 10:
                        self.boot_history.pop(0)
            except Exception as e:
                print(f"Boot time check error: {e}")

            # Get additional boot measurements if TPM is available
            if boot_status['boot_integrity']:
                try:
                    tpm_info = self._run_powershell_command("Get-TpmEndorsementKeyInfo")
                    if tpm_info:
                        boot_status['boot_measurements'] = tpm_info
                except Exception as e:
                    print(f"TPM measurements error: {e}")

            # Determine overall security status
            secure_factors = [
                boot_status['secure_boot'],
                boot_status['boot_integrity'],
                boot_status['boot_mode'] == 'UEFI',
                boot_status.get('bitlocker_status', {}).get('protection') == 'On'
            ]
            
            secure_count = sum(1 for factor in secure_factors if factor)
            if secure_count == len(secure_factors):
                boot_status['status'] = 'Secure'
            elif secure_count > 0:
                boot_status['status'] = 'Partially Secure'
            else:
                boot_status['status'] = 'Insecure'

            self.status_queue.put(('boot_status', boot_status))
        except Exception as e:
            error_msg = f"Boot status check error: {str(e)}"
            print(error_msg)
            self.status_queue.put(('boot_status', {
                'status': 'Error',
                'error': error_msg,
                'secure_boot': False,
                'boot_integrity': False,
                'boot_measurements': [],
                'last_boot_time': None,
                'boot_mode': 'Unknown',
                'boot_device': 'Unknown',
                'firmware_type': 'Unknown',
                'boot_status': 'Unknown'
            }))

    def _check_iommu_async(self):
        """Check IOMMU status in background"""
        try:
            virtualization_enabled = False
            iommu_enabled = False
            iommu_groups = []

            # Check virtualization
            result = self._run_powershell_command("systeminfo | Select-String 'Virtualization Enabled In Firmware'")
            if result and isinstance(result, dict):
                virtualization_enabled = 'Yes' in str(result)

            # Check IOMMU
            result = self._run_powershell_command("bcdedit | Select-String 'iommu'")
            if result and isinstance(result, dict):
                iommu_enabled = True

            # Check IOMMU groups
            if iommu_enabled:
                devices = self._run_powershell_command(
                    "Get-WmiObject Win32_PnPEntity | Where-Object {$_.ConfigManagerErrorCode -eq 0} | Select-Object Name, DeviceID | ConvertTo-Json"
                )
                if devices:
                    if isinstance(devices, list):
                        iommu_groups = devices
                    elif isinstance(devices, dict):
                        iommu_groups = [devices]

            self.status_queue.put(('iommu', {
                'status': 'Enabled' if (virtualization_enabled and iommu_enabled) else 'Disabled',
                'virtualization_enabled': virtualization_enabled,
                'iommu_enabled': iommu_enabled,
                'iommu_groups': iommu_groups
            }))
        except Exception as e:
            self.status_queue.put(('iommu', {'status': 'Error', 'error': str(e)}))

    def _check_tpm_async(self):
        """Check TPM status in background"""
        try:
            tpm_info = self._run_powershell_command(
                "Get-Tpm | Select-Object TpmPresent, TpmEnabled, TpmReady, SpecVersion, ManufacturerId"
            )
            
            if tpm_info:
                self.status_queue.put(('tpm', {
                    'status': 'Ready' if tpm_info.get('TpmReady', False) else 'Not Ready',
                    'tpm_present': tpm_info.get('TpmPresent', False),
                    'tpm_enabled': tpm_info.get('TpmEnabled', False),
                    'tpm_ready': tpm_info.get('TpmReady', False),
                    'tpm_version': tpm_info.get('SpecVersion'),
                    'tpm_manufacturer': tpm_info.get('ManufacturerId')
                }))
            else:
                self.status_queue.put(('tpm', {'status': 'Error', 'error': 'Failed to get TPM info'}))
        except Exception as e:
            self.status_queue.put(('tpm', {'status': 'Error', 'error': str(e)}))

    def _check_secure_boot_async(self):
        """Check Secure Boot status in background"""
        try:
            result = self._run_powershell_command("Confirm-SecureBootUEFI")
            if result and isinstance(result, dict):
                secure_boot_enabled = result.get('SecureBoot', False)
            else:
                secure_boot_enabled = False

            self.status_queue.put(('secure_boot', {
                'status': 'Enabled' if secure_boot_enabled else 'Disabled',
                'secure_boot_enabled': secure_boot_enabled
            }))
        except Exception as e:
            self.status_queue.put(('secure_boot', {'status': 'Error', 'error': str(e)}))

    def _monitor_system_resources_async(self):
        """Monitor system resources in background"""
        try:
            # Get CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Get memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Get disk usage
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            
            # Get network I/O
            net_io = psutil.net_io_counters()
            
            # Get system uptime
            uptime = datetime.now() - datetime.fromtimestamp(psutil.boot_time())
            
            # Update system metrics
            self.system_metrics = {
                'cpu_usage': cpu_percent,
                'memory_usage': memory_percent,
                'disk_usage': disk_percent,
                'network_io': {
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv,
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv
                },
                'uptime': str(uptime).split('.')[0]  # Remove microseconds
            }
            
            # Log resource usage securely
            self.crypto.secure_log(
                f"System Resources - CPU: {cpu_percent}%, Memory: {memory_percent}%, Disk: {disk_percent}%",
                self.secure_log_file
            )
            
            self.status_queue.put(('system_metrics', self.system_metrics))
        except Exception as e:
            error_msg = f"System metrics monitoring error: {str(e)}"
            print(error_msg)
            self.crypto.secure_log(error_msg, self.secure_log_file)
            self.status_queue.put(('system_metrics', {'status': 'Error', 'error': error_msg}))

    def _fetch_trusted_vendors(self):
        """Fetch the list of trusted PCI vendors from PCI-IDs database"""
        try:
            # Use PCI-IDs database API
            response = requests.get('https://pci-ids.ucw.cz/v2.2/pci.ids', timeout=10)
            if response.status_code == 200:
                vendors = {}
                current_vendor = None
                
                for line in response.text.split('\n'):
                    if line.startswith('#') or not line.strip():
                        continue
                    if not line.startswith('\t'):  # Vendor line
                        parts = line.split('  ', 1)
                        if len(parts) == 2:
                            vendor_id = parts[0].strip()
                            vendor_name = parts[1].strip()
                            # Add major trusted vendors
                            if any(trusted in vendor_name.lower() for trusted in [
                                'intel', 'amd', 'nvidia', 'qualcomm', 'broadcom', 'microsoft',
                                'apple', 'samsung', 'realtek', 'mediatek', 'texas instruments',
                                'nxp', 'marvell', 'xilinx', 'cisco', 'dell', 'hp', 'ibm', 'lenovo'
                            ]):
                                vendors[vendor_id] = vendor_name

                return vendors
        except Exception as e:
            print(f"Error fetching trusted vendors: {e}")
        
        # Fallback to a basic list if fetch fails
        return {
            '8086': 'Intel Corporation',
            '1022': 'Advanced Micro Devices, Inc. [AMD]',
            '10DE': 'NVIDIA',
            '1002': 'Advanced Micro Devices, Inc. [AMD/ATI]',
            '14E4': 'Broadcom Inc.',
            '168C': 'Qualcomm Atheros',
            '1414': 'Microsoft Corporation',
            '106B': 'Apple Inc.',
            '10EC': 'Realtek Semiconductor Co., Ltd.',
            '144D': 'Samsung Electronics Co Ltd'
        }

    def get_trusted_vendors(self):
        """Get the list of trusted vendors, updating if necessary"""
        with self._vendor_update_lock:
            current_time = datetime.now()
            # Update vendor list every 24 hours or if it hasn't been fetched yet
            if (self._trusted_vendors is None or 
                self._last_vendor_update is None or 
                (current_time - self._last_vendor_update).days >= 1):
                self._trusted_vendors = self._fetch_trusted_vendors()
                self._last_vendor_update = current_time
            return self._trusted_vendors

    def _check_pci_devices_async(self):
        """Check PCI devices in background"""
        try:
            wmi = win32com.client.GetObject("winmgmts:")
            pci_devices = wmi.ExecQuery("SELECT * FROM Win32_PnPEntity WHERE PNPClass = 'Display' OR PNPClass = 'System' OR PNPClass = 'HDC' OR PNPClass = 'SCSIAdapter' OR PNPClass = 'USB'")
            
            suspicious_devices = []
            trusted_vendors = self.get_trusted_vendors()
            
            for device in pci_devices:
                try:
                    device_info = {
                        'name': getattr(device, 'Name', 'Unknown'),
                        'device_id': getattr(device, 'DeviceID', 'Unknown'),
                        'manufacturer': getattr(device, 'Manufacturer', 'Unknown'),
                        'status': 'OK',
                        'suspicious_reasons': []
                    }
                    
                    # Check if device is from a trusted vendor
                    vendor_id = None
                    if device_info['device_id'].startswith('PCI\\VEN_'):
                        vendor_id = device_info['device_id'].split('VEN_')[1][:4].upper()
                    
                    if vendor_id and vendor_id not in trusted_vendors:
                        device_info['status'] = 'Warning'
                        device_info['suspicious_reasons'].append(f'Untrusted vendor (ID: {vendor_id})')
                        suspicious_devices.append(device_info)
                    
                except Exception as e:
                    print(f"Error processing device: {e}")
                    continue

            status = 'Warning' if suspicious_devices else 'OK'
            self.status_queue.put(('pci_devices', {
                'status': status,
                'suspicious_devices': suspicious_devices,
                'count': len(suspicious_devices)
            }))
        except Exception as e:
            error_msg = f"PCI devices check error: {str(e)}"
            print(error_msg)
            self.status_queue.put(('pci_devices', {
                'status': 'Error',
                'error': error_msg,
                'suspicious_devices': [],
                'count': 0
            }))

    def _check_memory_integrity_async(self):
        """Check memory integrity and monitor memory access in background"""
        try:
            memory_status = {
                'status': 'OK',
                'anomalies': [],
                'memory_access': [],
                'integrity_checks': [],
                'metrics': {}
            }

            # Get memory metrics
            try:
                result = self._run_powershell_command("""
                $memory = Get-Counter '\\Memory\\*' -ErrorAction SilentlyContinue
                $processes = Get-Process | Where-Object { $_.WorkingSet -gt 100MB }
                $memoryAccess = Get-WmiObject Win32_PerfFormattedData_PerfOS_Memory | 
                    Select-Object AvailableBytes, CacheBytes, CommittedBytes, PoolNonpagedBytes, PoolPagedBytes
                
                @{
                    MemoryMetrics = @{
                        Available = $memoryAccess.AvailableBytes
                        Cache = $memoryAccess.CacheBytes
                        Committed = $memoryAccess.CommittedBytes
                        NonPagedPool = $memoryAccess.PoolNonpagedBytes
                        PagedPool = $memoryAccess.PoolPagedBytes
                    }
                    LargeProcesses = $processes | Select-Object Name, Id, WorkingSet, PrivateMemorySize, VirtualMemorySize
                } | ConvertTo-Json""")

                if result and isinstance(result, dict):
                    memory_status['metrics'] = result.get('MemoryMetrics', {})
                    
                    # Check for suspicious memory patterns
                    large_processes = result.get('LargeProcesses', [])
                    for process in large_processes:
                        if isinstance(process, dict):
                            # Check for unusual memory patterns
                            if process.get('WorkingSet', 0) > 1000000000:  # More than 1GB
                                anomaly = {
                                    'type': 'High Memory Usage',
                                    'process': process.get('Name', 'Unknown'),
                                    'pid': process.get('Id', 0),
                                    'working_set': process.get('WorkingSet', 0),
                                    'timestamp': datetime.now().isoformat()
                                }
                                memory_status['anomalies'].append(anomaly)
                                # Log the anomaly securely
                                self.crypto.secure_log(
                                    f"High memory usage detected: {process.get('Name', 'Unknown')} (PID: {process.get('Id', 0)}) using {process.get('WorkingSet', 0):,} bytes",
                                    self.secure_log_file
                                )

            except Exception as e:
                error_msg = f"Memory metrics error: {e}"
                print(error_msg)
                self.crypto.secure_log(error_msg, self.secure_log_file)

            # Check for suspicious memory access patterns
            try:
                result = self._run_powershell_command("""
                $memoryAccess = Get-WmiObject Win32_PerfFormattedData_PerfOS_Memory
                $processes = Get-Process | Where-Object { $_.WorkingSet -gt 100MB }
                
                @{
                    MemoryAccess = @{
                        Available = $memoryAccess.AvailableBytes
                        Cache = $memoryAccess.CacheBytes
                        Committed = $memoryAccess.CommittedBytes
                        NonPagedPool = $memoryAccess.PoolNonpagedBytes
                        PagedPool = $memoryAccess.PoolPagedBytes
                    }
                    SuspiciousProcesses = $processes | Where-Object { 
                        $_.WorkingSet -gt 1000000000 -or 
                        $_.PrivateMemorySize -gt 1000000000 -or
                        $_.VirtualMemorySize -gt 2000000000
                    } | Select-Object Name, Id, WorkingSet, PrivateMemorySize, VirtualMemorySize
                } | ConvertTo-Json""")

                if result and isinstance(result, dict):
                    suspicious_processes = result.get('SuspiciousProcesses', [])
                    for process in suspicious_processes:
                        if isinstance(process, dict):
                            access_info = {
                                'process': process.get('Name', 'Unknown'),
                                'pid': process.get('Id', 0),
                                'working_set': process.get('WorkingSet', 0),
                                'private_memory': process.get('PrivateMemorySize', 0),
                                'virtual_memory': process.get('VirtualMemorySize', 0),
                                'timestamp': datetime.now().isoformat()
                            }
                            memory_status['memory_access'].append(access_info)
                            # Log suspicious process securely
                            self.crypto.secure_log(
                                f"Suspicious process detected: {process.get('Name', 'Unknown')} (PID: {process.get('Id', 0)})",
                                self.secure_log_file
                            )

            except Exception as e:
                error_msg = f"Memory access check error: {e}"
                print(error_msg)
                self.crypto.secure_log(error_msg, self.secure_log_file)

            # Check memory integrity
            try:
                result = self._run_powershell_command("""
                $integrity = @{
                    KernelMemory = (Get-WmiObject Win32_OperatingSystem).TotalVisibleMemorySize
                    PageFaults = (Get-Counter '\\Memory\\Page Faults/sec').CounterSamples.CookedValue
                    CacheFaults = (Get-Counter '\\Memory\\Cache Faults/sec').CounterSamples.CookedValue
                }
                $integrity | ConvertTo-Json""")

                if result and isinstance(result, dict):
                    integrity_check = {
                        'kernel_memory': result.get('KernelMemory', 0),
                        'page_faults': result.get('PageFaults', 0),
                        'cache_faults': result.get('CacheFaults', 0),
                        'timestamp': datetime.now().isoformat()
                    }
                    memory_status['integrity_checks'].append(integrity_check)

                    # Check for integrity anomalies
                    if result.get('PageFaults', 0) > 1000:  # High page fault rate
                        anomaly = {
                            'type': 'High Page Fault Rate',
                            'value': result.get('PageFaults', 0),
                            'timestamp': datetime.now().isoformat()
                        }
                        memory_status['anomalies'].append(anomaly)
                        # Log the anomaly securely
                        self.crypto.secure_log(
                            f"High page fault rate detected: {result.get('PageFaults', 0)} faults/sec",
                            self.secure_log_file
                        )

            except Exception as e:
                error_msg = f"Memory integrity check error: {e}"
                print(error_msg)
                self.crypto.secure_log(error_msg, self.secure_log_file)

            # Update status based on findings
            if memory_status['anomalies']:
                memory_status['status'] = 'Warning'
            elif memory_status['memory_access']:
                memory_status['status'] = 'Monitoring'
            else:
                memory_status['status'] = 'OK'

            self.status_queue.put(('memory_integrity', memory_status))
        except Exception as e:
            error_msg = f"Memory integrity check error: {str(e)}"
            print(error_msg)
            self.crypto.secure_log(error_msg, self.secure_log_file)
            self.status_queue.put(('memory_integrity', {
                'status': 'Error',
                'error': error_msg,
                'anomalies': [],
                'memory_access': [],
                'integrity_checks': [],
                'metrics': {}
            }))

    def _check_debugger_async(self):
        """Check for common debuggers and debugging environments"""
        try:
            # Method 1: Check for common debugger process names
            debugger_processes = [
                "pycharm",
                "pydevd",
                "vscode",
                "code.exe",
                "python-debug",
                "pdb",
                "winpdb",
                "pytools",
                "debugpy"
            ]
            
            detected_debuggers = []
            
            # Check for running debugger processes
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    proc_name = proc.info['name'].lower() if proc.info['name'] else ""
                    proc_cmdline = " ".join(proc.info['cmdline']).lower() if proc.info['cmdline'] else ""
                    
                    # Check process name against known debuggers
                    for debugger in debugger_processes:
                        if (debugger in proc_name or 
                            debugger in proc_cmdline):
                            detected_debuggers.append({
                                'name': proc.info['name'],
                                'pid': proc.info['pid'],
                                'cmdline': proc.info['cmdline'][:3]  # Show only first 3 args for privacy
                            })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

            # Method 2: Check environment variables that indicate debuggers
            debug_env_vars = ['PYTHONBREAKPOINT', 'PYDEVD_LOAD_VALUES_ASYNC', 
                             'PYTHONDEBUG', 'PYTHONINSPECT', 'DEBUG_PY', 
                             'DEBUGPY_LAUNCHER_PORT', 'VSCODE_DEBUG_PORT']
            
            for var in debug_env_vars:
                if var in os.environ:
                    detected_debuggers.append({
                        'name': f"Environment variable: {var}",
                        'value': "[REDACTED]",  # Don't show actual values for security
                        'type': 'env_var'
                    })
            
            # Method 3: Check for trace functions which may indicate debuggers
            import sys
            if sys.gettrace() is not None:
                detected_debuggers.append({
                    'name': 'Python trace function',
                    'type': 'trace_hook',
                    'info': 'sys.gettrace() returned a function'
                })

            # Determine status and log the result
            if detected_debuggers:
                status = 'Warning'
                error_msg = "Debugger detected! This may compromise system security."
                self.crypto.secure_log(f"Debugger detection: {detected_debuggers}", self.secure_log_file)
                
                # Put the result in the queue
                self.status_queue.put(('debugger', {
                    'status': status,
                    'error': error_msg,
                    'detected_debuggers': detected_debuggers,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }))
                
                # Raise security exception to alert user
                raise SecurityException("Debugger detected! Application cannot run in debug mode for security reasons.")
            else:
                # No debugger found
                self.status_queue.put(('debugger', {
                    'status': 'OK',
                    'detected_debuggers': [],
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }))
                
        except Exception as e:
            if isinstance(e, SecurityException):
                # Re-raise security exceptions
                raise
            
            error_msg = f"Debugger check error: {str(e)}"
            print(error_msg)
            self.crypto.secure_log(error_msg, self.secure_log_file)
            self.status_queue.put(('debugger', {
                'status': 'Error',
                'error': error_msg,
                'detected_debuggers': []
            }))

    def get_all_status(self) -> Dict[str, Any]:
        """Get all hardware security status asynchronously"""
        try:
            # First check for debuggers (no threading to allow exception propagation)
            self._check_debugger_async()
            
            # If no debugger found, proceed with other checks
            # Submit all checks to thread pool
            futures = [
                self.thread_pool.submit(self._check_unsigned_drivers_async),
                self.thread_pool.submit(self._check_connections_async),
                self.thread_pool.submit(self._check_boot_status_async),
                self.thread_pool.submit(self._check_iommu_async),
                self.thread_pool.submit(self._check_tpm_async),
                self.thread_pool.submit(self._check_secure_boot_async),
                self.thread_pool.submit(self._monitor_system_resources_async),
                self.thread_pool.submit(self._check_pci_devices_async),
                self.thread_pool.submit(self._check_memory_integrity_async)
            ]

            # Wait for all futures to complete
            concurrent.futures.wait(futures)

            # Collect results from queue
            results = {}
            while not self.status_queue.empty():
                key, value = self.status_queue.get_nowait()
                results[key] = value

            return results
        except SecurityException as e:
            # Handle security exceptions
            return {
                'status': 'Critical Security Error',
                'error': str(e),
                'debugger': {
                    'status': 'Critical',
                    'error': str(e)
                }
            }

class SecurityException(Exception):
    """Exception raised for security violations"""
    pass 