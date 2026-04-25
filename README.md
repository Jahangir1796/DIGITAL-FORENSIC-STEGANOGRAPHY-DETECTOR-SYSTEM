# DIGITAL-FORENSIC-STEGANOGRAPHY-DETECTOR-SYSTEM
📌 Overview

This project is a comprehensive steganography detection and forensic analysis system developed in Python. It is designed to detect, extract, analyze, and securely handle hidden data embedded inside digital images using steganographic techniques.

Unlike basic tools, this system simulates a real-world digital forensic workflow, integrating detection, encryption, evidence handling, integrity verification, and report generation into a single platform.

The project is suitable for:

Cybersecurity students
Digital forensic investigations
Academic research
Ethical hacking and CTF learning
🚀 Features
🔍 Steganography Detection
Detects hidden data using LSB statistical analysis
Identifies suspicious images based on bit distribution
🧠 Image Analysis
Entropy calculation for randomness detection
Identifies unnatural patterns in images
📤 Data Extraction
Extracts hidden messages from stego images
Supports structured decoding using embedded headers
Password-based extraction supported
🔐 Encryption & Decryption
Secure encryption before embedding
Multi-layer encryption support
Handles text and file-based data
🧾 Digital Forensics Workflow
Case creation and management
Evidence handling (no modification of original files)
Chain of custody simulation
🧬 Integrity Verification
SHA-256 hashing for evidence validation
Detects any tampering in files
📊 Advanced Security Analysis
PSNR (Peak Signal-to-Noise Ratio)
MSE (Mean Squared Error)
Chi-square analysis
RS steganalysis
👤 User Authentication
Secure login and registration system
Password hashing for protection
🖥️ Graphical User Interface (GUI)
Built using Tkinter
Easy-to-use interface
Separate tabs for encoding, decoding, and analysis
📄 Report Generation
Automatically generates forensic reports
Includes all analysis results and metadata
🏗️ Project Structure
STEG_DETECTOR/
│
├── lsb_engine.py        # Core LSB encoding & decoding
├── detector.py          # Steganography detection logic
├── extractor.py         # Hidden data extraction
├── analyzer.py          # Entropy analysis
├── crypto_utils.py      # Encryption & decryption
├── multi_layer.py       # Multi-layer encryption system
├── security_analysis.py # Advanced image analysis
├── auth_system.py       # User authentication
├── case_manager.py      # Forensic case handling
├── integrity.py         # Hashing & integrity checks
├── reporter.py          # Report generation
├── monitor.py           # Activity monitoring
├── stego_gui.py         # GUI application
├── main_forensic.py     # Main forensic workflow (CLI)
│
├── evidence/            # Stored evidence files
├── reports/             # Generated forensic reports
├── users.json           # User database
└── README.md
⚙️ Installation
1. Clone the Repository
git clone https://github.com/your-username/stego-detector.git
cd stego-detector
2. Install Dependencies
pip install -r requirements.txt

If requirements.txt is not available, install manually:

pip install numpy pillow matplotlib cryptography
▶️ Usage
🔹 Run GUI Application
python stego_gui.py
🔹 Run Forensic CLI
python main_forensic.py
🔐 How It Works

The system follows a structured forensic workflow:

Image is added as evidence
SHA-256 hash is generated for integrity
LSB statistical analysis is performed for detection
Entropy and security metrics are calculated
Hidden data is extracted (if present)
Final forensic report is generated
📊 Sample Output
Stego Detection: True / False
LSB Ratio: ~0.50 (Suspicious)
Entropy Value: High / Normal
Extracted Message: "Hidden Data..."
Hash: SHA-256 fingerprint
🧪 Technologies Used
Python
NumPy
Pillow (PIL)
Matplotlib
Cryptography Library
Tkinter (GUI)
🔒 Security Highlights
Password-based data embedding
Multi-layer encryption (AES, ChaCha20, etc.)
Secure key derivation
Evidence integrity verification
📈 Future Improvements
Machine Learning-based steganography detection
Support for audio and video steganography
Cloud-based forensic analysis
Real-time monitoring system
🤝 Contribution

Contributions are welcome! If you'd like to improve this project:

Fork the repository
Create a new branch
Make your changes
Submit a pull request
📜 License

This project is for educational and research purposes only.

👨‍💻 Author

Jahangir Ahmed
Cybersecurity & Digital Forensics Enthusiast
