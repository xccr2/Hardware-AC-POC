- Real-time monitoring of hardware security features
- Visual status indicators with color coding
- Auto-refresh every 5 seconds
- Manual refresh option
- Detailed status information for each security feature

## Requirements

- Windows 10 or later
- Python 3.8 or later
- Administrator privileges (for some security checks)

## Installation

1. Clone this repository or download the files
2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the application with administrator privileges:
```bash
python main.py
```

2. The application will display three main sections:
   - IOMMU Status
   - TPM Status
   - Secure Boot Status

3. Each section shows:
   - Current status (color-coded)
   - Detailed information about the feature
   - Any errors or issues detected

4. Use the "Refresh" button to manually update the status

## Security Features Monitored

### IOMMU
- Checks if virtualization is enabled in firmware
- Verifies IOMMU status in BIOS

### TPM
- Checks TPM presence
- Verifies TPM is enabled and ready for use
- Monitors TPM status and readiness

### Secure Boot
- Monitors Secure Boot status
- Verifies if Secure Boot is enabled in UEFI

## Notes

- Some features may require specific hardware support
- Administrator privileges are required for accurate status reporting
- The application uses Windows Management Instrumentation (WMI) for system information 