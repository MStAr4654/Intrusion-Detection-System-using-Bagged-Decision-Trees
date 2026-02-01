# Intrusion-Detection-System-using-Bagged-Decision-Trees
This repo is created for the sole Purpose of storing the files used to create the project of "Intrusion Detection System using Bagged Decision Trees". It was created as a project for the AIML Lab Course in 5th semester.

## Intrusion Detection System using Bagged Decision Trees
# 📌 Project Overview

This project implements a Machine Learning–based Intrusion Detection System (IDS) using Bagged Decision Trees, trained on the NSL-KDD dataset.
The system is capable of detecting malicious network traffic by analyzing packet data captured using Wireshark from a VirtualBox Ubuntu virtual machine running on a macOS host.

The workflow includes:

1. Training an ML model using NSL-KDD

2. Saving the trained model and normalization parameters

3. Capturing real or simulated network traffic using PCAP files

4. Classifying traffic as Normal or Intrusion using MATLAB

## 🧰 Software & System Requirements 
# 1. Host System

macOS / Windows / Linux (tested on macOS)

Minimum 8 GB RAM recommended

# 2. Required Software
Software	Version (Recommended)
MATLAB	R2023a or later
Wireshark	Latest stable version
Oracle VirtualBox	7.x
Ubuntu (VM)	Ubuntu 20.04 LTS or later


# Step 1: Install MATLAB

* Download MATLAB from: https://www.mathworks.com

* During installation, ensure the following toolboxes are installed:

* Statistics and Machine Learning Toolbox

* Signal Processing Toolbox (recommended)


# Step 2: Install VirtualBox & Ubuntu

* Download Oracle VirtualBox

* Download Ubuntu ISO (20.04 LTS recommended)

* Now create a new VM with the following specifications:

1. Type: Linux

2. Version: Ubuntu (64-bit)

3. RAM: ≥ 4 GB

4. Network Adapter: NAT

5. Install Ubuntu inside the VM

6.Ensure internet connectivity inside Ubuntu


# Step 3: Install Wireshark
On Host (macOS / Windows)

* Download Wireshark from: https://www.wireshark.org

* During installation, allow:

* Packet capture permissions

* Network interface access

* After installing the Wireshark, run it

[Optional] On Ubuntu

```
sudo apt update
sudo apt install wireshark
```

# Step 4: Clone the GitHub Repository
```
git clone https://github.com/MStAr4654/Intrusion-Detection-System-using-Bagged-Decision-Trees.git
cd Intrusion-Detection-System-using-Bagged-Decision-Trees
```

# Step 5: Understanding Repository Structure

│── Dataset_NSL-KDD.zip        → Training dataset

│── IDS_Trainer.m              → Model training script

│── IDS_Model.mat              → Saved trained ML model

│── IDS_Normalization.mat      → Feature normalization parameters

│── IDS_Model_Comparison.m     → Model performance evaluation

│── LiveDetect_HostCapture.m   → Live / PCAP-based intrusion detection

│── X_test.mat                 → Test feature data

│── PCAP_Files.zip             → Network traffic samples

│── IDS_block_diagram.png      → System architecture diagram

│── README.md                  → Project documentation


# Step 6: Train the Intrusion Detection Model

* Extract Dataset_NSL-KDD.zip

* Open MATLAB and set the project folder as the Current Folder

* Run:
```
IDS_Trainer.m
```

This script will:

* Load the NSL-KDD dataset

* Preprocesses and normalizes features

* Trains a Bagged Decision Tree classifier

* And finally saves the trained model as: ***IDS_Model.mat***


# Step 7: Evaluation of Model Performance

Run:
```
IDS_Model_Comparison.m
```

This script will:

* Test the trained model on unseen data

* Generate accuracy metrics and comparisons

* Helps validate IDS effectiveness


_Note: This step is crucial to know the IP address of your test subject i.e. the Ubuntu VM_

You can verify the connection using the command

For the Host Machine
```
ifconfig (for Mac)
ipconfig (for Windows)
```

For the Ubuntu on VirtualBox
```
hostname -I (IP Address of the network)
```

You need to match the IP Addresses in both the terminals / cmd windows in order to find 
the network name to be used in the command ***tcpreplay***


# Step 8: Capture Network Traffic (PCAP Files)
***Option A: Live Capture using Wireshark***

* Start Wireshark on host machine (Your Mac / Windows / Linux)

* Select the network interface connected to VirtualBox

* Start capturing packets

Perform certain actions inside Ubuntu VM such as:

* Web browsing

* File downloads

* Network scans (for testing)

Now, stop capture on Wireshark and save as .pcap

***Option B: Use Provided PCAP Files***

* Extract PCAP_Files.zip

* Use pre-captured traffic for simulation

# Run Intrusion Detection on PCAP / Live Traffic

* Open MATLAB

Run:
```
LiveDetect_HostCapture.m
```

This script will:

* Read packet capture data

* Extracts relevant network features

* Applies normalization

* Uses the trained model for classification

# Outputs:

A graph where it will show if the packets captured are:

1. Normal Traffic --> 0 (on the graph)

2. Intrusion Detected --> 1 (on the graph)




## System Workflow Summary

* NSL-KDD dataset → Model training

* Model saved for reuse

* Network traffic captured via Wireshark

* Features extracted from PCAP files

* ML model classifies traffic in real time or offline

* Intrusion alerts generated

<img width="167" height="153" alt="IDS_block_diagram" src="https://github.com/user-attachments/assets/d31be3b9-2953-49a3-af5e-b715ace762cd" />

