# 🛡️ ROMs Hash Checker - Mc-security

A simple and user-friendly **ROMs Hash Checker** built with **Python** and **PyQt6**.  
It allows you to verify the integrity of your ROMs by comparing their **MD5 and SHA1 hashes** against `.dat` databases.

---

## ✨ Features

- Compute **MD5** and **SHA1** hashes of ROM files (`.iso`)  
- Compare against `.dat` hash databases (placed in the `hashs` folder)  
- Supports **recursive folder scanning**  
- **Progress bar** for real-time analysis tracking  
- **Results log** with clear FOUND / NOT FOUND messages  
- Cross-platform GUI using PyQt6  

---

## 📦 Requirements

- Python **3.10+**  

## 🛠️ How to use

- Clone the repository:

  ```bash
  git clone https://github.com/Mc-gabys/ROMs-Hash-Checker
- Go to the project folder:

  ```bash
  cd ROMs-Hash-Checker
- Install dependencies:

  ```bash
  python -m pip install -r requirements.txt
- Run the script:

  ```bash
  python3 main.py
- In the GUI:

  - Select a single `.iso` file or a folder containing ROMs.
  - Check "Analyze recursively" if you want to scan subfolders.
  - Click **Start Analysis**.
  - Follow the log to see which ROMs are found in the database.

---

## 🔒 Notes

- Only .iso files are analyzed.
- The program reads .dat files to build its hash database. Ensure they are valid XML DATs.
- Progress and logs update in real-time during analysis.

---

## ❤️ Support me on KoFi

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/N4N61K5R2A)

---

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
