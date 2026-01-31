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


🛠️ Step 1: Install MATLAB

Download MATLAB from: https://www.mathworks.com

During installation, ensure the following toolboxes are installed:

Statistics and Machine Learning Toolbox

Signal Processing Toolbox (recommended)


🛠️ Step 2: Install VirtualBox & Ubuntu

Download Oracle VirtualBox

Download Ubuntu ISO (20.04 LTS recommended)

Create a new VM:

Type: Linux

Version: Ubuntu (64-bit)

RAM: ≥ 4 GB

Network Adapter: NAT

Install Ubuntu inside the VM

Ensure internet connectivity inside Ubuntu


🛠️ Step 3: Install Wireshark
On Host (macOS / Windows)

Download Wireshark from: https://www.wireshark.org

During installation, allow:

Packet capture permissions

Network interface access

After installing the 
On Ubuntu (optional)
sudo apt update
sudo apt install wireshark

📂 Step 4: Clone the GitHub Repository
git clone https://github.com/MStAr4654/Intrusion-Detection-System-using-Bagged-Decision-Trees.git
cd Intrusion-Detection-System-using-Bagged-Decision-Trees

📊 Step 5: Understanding Repository Structure
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

🧪 Step 6: Train the Intrusion Detection Model

Extract Dataset_NSL-KDD.zip

Open MATLAB and set the project folder as the Current Folder

Run:

IDS_Trainer


This script:

Loads NSL-KDD dataset

Preprocesses and normalizes features

Trains a Bagged Decision Tree classifier

Saves:

IDS_Model.mat

IDS_Normalization.mat

📈 Step 7: Evaluate Model Performance

Run:

IDS_Model_Comparison


This script:

Tests the trained model on unseen data

Generates accuracy metrics and comparisons

Helps validate IDS effectiveness

🌐 Step 8: Capture Network Traffic (PCAP Files)
Option A: Live Capture using Wireshark

Start Wireshark on host machine

Select the network interface connected to VirtualBox

Start capturing packets

Perform actions inside Ubuntu VM:

Web browsing

File downloads

Network scans (for testing)

Stop capture and save as .pcap

Option B: Use Provided PCAP Files

Extract PCAP_Files.zip

Use pre-captured traffic for simulation

🚨 Step 9: Run Intrusion Detection on PCAP / Live Traffic

Open MATLAB

Run:

LiveDetect_HostCapture


This script:

Reads packet capture data

Extracts relevant network features

Applies normalization

Uses the trained model for classification

Outputs:

Normal Traffic

Intrusion Detected

🧠 Step 10: System Workflow Summary

NSL-KDD dataset → Model training

Model saved for reuse

Network traffic captured via Wireshark

Features extracted from PCAP files

ML model classifies traffic in real time or offline

Intrusion alerts generated

(Refer to IDS_block_diagram.png for visual representation.)
