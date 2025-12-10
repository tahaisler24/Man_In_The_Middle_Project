📌 Man In The Middle Project (ARP Spoofing Tool)

This project is a simple Man-in-the-Middle (MITM) tool written in Python.
It uses ARP spoofing to place your computer between the target machine and the gateway (router).

The tool can:

Enable IP forwarding

Get MAC addresses using ARP

Send ARP spoofing packets

Restore the network when the attack stops

This project is created for learning and educational purposes only.

⚠️ Warning

This tool is only for cybersecurity education.
Do not use it on networks you do not own or do not have permission to test.
Unauthorized use can be illegal.

📁 Project Structure
Man_In_The_Middle_Project/
│
├── main.py    # Main ARP spoofing script
└── README.md  # Documentation

🚀 Features

Simple command-line interface

One parser for all arguments (-e, -t, -g)

Clean IP forwarding activation

ARP spoofing between target and gateway

Network reset after CTRL + C

Beginner-friendly code and structure

🛠 Requirements

Before running the script, install:

pip install scapy


This script must run with sudo because ARP packets need root permissions:

sudo python3 main.py ...

📌 Command-Line Arguments
Argument	Description
-e or --enable	Enable IP forwarding
-t or --target	Target machine IP
-g or --gateway	Gateway (router) IP
▶️ Usage Example

Start ARP spoofing:

sudo python3 main.py -e -t 10.10.10.18 -g 10.10.10.254


Explanation:

-e → Enables IP forwarding

-t → Target device IP

-g → Gateway IP

After running, the tool sends ARP packets every 3 seconds until you stop it:

CTRL + C


When you stop the attack, the program restores the network automatically.

🔍 How It Works (Simple Explanation)

The script sends fake ARP packets to the target saying:
→ “I am the gateway.”

Then it sends fake ARP packets to the gateway saying:
→ “I am the target.”

Both machines start sending traffic through your machine.

This creates a MITM position.

When you exit, the program sends correct ARP packets to fix the ARP table.

👤 Author

GitHub: tahaisler24


This project is part of my cybersecurity learning journey.
