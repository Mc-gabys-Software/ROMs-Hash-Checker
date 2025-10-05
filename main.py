import sys
import os
import hashlib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Optional

from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QPushButton, QLineEdit, QFileDialog, QProgressBar, QMessageBox, QPlainTextEdit, QHBoxLayout, QCheckBox, QTreeWidget, QTreeWidgetItem, QTabWidget, QTextEdit
from PyQt6.QtCore import Qt, QThread, pyqtSignal

HASH_FOLDER = "hashs"
EXTENSIONS_FILE = "extensions.txt"

HashDatabase = Dict[str, Dict[str, str]]

def compute_file_hashes(file_path: str, progress_callback: Optional[callable] = None) -> Dict[str, str]:
    buf_size = 65536  
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()

    try:
        total_size = os.path.getsize(file_path)
        read_bytes = 0

        with open(file_path, "rb") as f:
            while chunk := f.read(buf_size):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                read_bytes += len(chunk)
                if progress_callback:
                    progress_callback(int((read_bytes / total_size) * 100))
        
        return {
            "md5": md5_hash.hexdigest(),
            "sha1": sha1_hash.hexdigest(),
        }

    except IOError as e:
        print(f"Error reading file {file_path}: {e}")
        return {}

def preprocess_dat_files() -> HashDatabase:
    hash_db: HashDatabase = {}
    dat_folder = Path(HASH_FOLDER)

    if not dat_folder.is_dir():
        print(f"Directory '{HASH_FOLDER}' does not exist.")
        return hash_db

    for dat_file in dat_folder.glob("*.dat"):
        try:
            tree = ET.parse(str(dat_file))
            root = tree.getroot()
            for game in root.findall(".//game"):
                game_name = game.get("name", "Unknown Game")
                for rom in game.findall("rom"):
                    md5 = rom.get("md5")
                    sha1 = rom.get("sha1")
                    rom_info = {"name": game_name, "dat_source": dat_file.name}
                    
                    if md5:
                        hash_db[md5.lower()] = rom_info
                    if sha1:
                        hash_db[sha1.lower()] = rom_info
        except ET.ParseError as e:
            print(f"Error parsing DAT file {dat_file}: {e}")

    return hash_db

class HashCheckThread(QThread):
    progress = pyqtSignal(int)
    log_message = pyqtSignal(str)
    found_roms = pyqtSignal(object)
    finished = pyqtSignal()

    def __init__(self, path_to_check: str, recursive: bool, hash_db: HashDatabase):
        super().__init__()
        self.path_to_check = path_to_check
        self.recursive = recursive
        self.hash_db = hash_db

    def run(self):
        files_to_check = []
        base_path = Path(self.path_to_check)
        found_files = 0

        if base_path.is_file():
            files_to_check.append(str(base_path))
        elif base_path.is_dir():
            self.log_message.emit(f"🔍 Searching for valid ROMs files in {self.path_to_check}...")
            pattern = "**/*.{ext}" if self.recursive else "*.{ext}"
            extensions = []
            if os.path.isfile(EXTENSIONS_FILE):
                with open(EXTENSIONS_FILE, "r") as ef:
                    extensions = [line.split()[0].lower() for line in ef if line.strip()]

            for ext in extensions:
                files_to_check.extend([str(p) for p in base_path.glob(pattern.format(ext=ext))])

        if not files_to_check:
            self.log_message.emit("ℹ️ No valid ROM files found to analyze.")
            self.finished.emit()
            return

        self.log_message.emit(f"▶️ Starting analysis of {len(files_to_check)} file(s).")
        total_files = len(files_to_check)

        for i, file_path_str in enumerate(files_to_check, 1):
            file_path = Path(file_path_str)
            relative_path = os.path.relpath(file_path, base_path.parent)

            self.log_message.emit(f"\n[{i}/{total_files}] Analyzing: {relative_path}")

            def file_progress_update(p: int):
                overall_progress = int(((i - 1 + p / 100) / total_files) * 100)
                self.progress.emit(overall_progress)

            hashes = compute_file_hashes(str(file_path), progress_callback=file_progress_update)
            if not hashes:
                self.log_message.emit(f"   └─ ⚠️ Error calculating hash.")
                continue

            md5 = hashes["md5"]
            sha1 = hashes["sha1"]

            found_info = self.hash_db.get(md5) or self.hash_db.get(sha1)

            if found_info:
                message = (
                    f"   └─ ✔️ FOUND: \"{found_info['name']}\"\n"
                    f"      (Source: {found_info['dat_source']})"
                )
                self.log_message.emit(message)
                info = {"file": relative_path, "name": found_info['name'], "source": found_info['dat_source']}
                self.found_roms.emit(info)
                found_files += 1
            else:
                self.log_message.emit(f"   └─ ❌ NOT FOUND in database.")
        
        self.progress.emit(100)
        self.log_message.emit(f"\n✅ Analysis complete. {found_files}/{total_files} files found on database.")
        self.finished.emit()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ROMs Hash Checker - Mc-tools")
        self.setGeometry(100, 100, 700, 500)
        try:
            with open("styles.qss", "r") as f:
                self.setStyleSheet(f.read())
        except FileNotFoundError:
            self.setStyleSheet("")

        self.hash_database = preprocess_dat_files()
        if not self.hash_database:
            QMessageBox.warning(
                self,
                "Warning",
                f"No hash database could be loaded from folder '{HASH_FOLDER}'.\n"
                "The application may not function as expected."
            )

        self.init_ui()
        self.hash_thread = None

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        central_layout = QVBoxLayout(main_widget)

        self.tabs = QTabWidget()
        central_layout.addWidget(self.tabs)

        main_tab = QWidget()
        main_layout = QVBoxLayout(main_tab)

        label = QLabel("ROMs Hash Checker by Mc-gabys")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(label)

        selection_layout = QHBoxLayout()

        self.path_line_edit = PathLineEdit()
        self.path_line_edit.setPlaceholderText("Select a valid ROM file or a ROMs folder")
        selection_layout.addWidget(self.path_line_edit)

        self.browse_file_btn = QPushButton("Browse for file...")
        self.browse_file_btn.clicked.connect(self.browse_path)
        selection_layout.addWidget(self.browse_file_btn)

        self.browse_folder_btn = QPushButton("Browse for folder...")
        self.browse_folder_btn.clicked.connect(self.browse_folder)
        selection_layout.addWidget(self.browse_folder_btn)

        main_layout.addLayout(selection_layout)

        controls_layout = QHBoxLayout()
        self.recursive_checkbox = QCheckBox("Analyze recursively")
        self.recursive_checkbox.setChecked(True)
        controls_layout.addWidget(self.recursive_checkbox)
        controls_layout.addStretch()

        self.start_analysis_btn = QPushButton("🚀 Start Analysis")
        self.start_analysis_btn.clicked.connect(self.start_analysis)
        controls_layout.addWidget(self.start_analysis_btn)
        main_layout.addLayout(controls_layout)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        main_layout.addWidget(self.progress_bar)

        main_layout.addWidget(QLabel("Results Log:"))
        self.results_text_edit = QPlainTextEdit()
        self.results_text_edit.setReadOnly(True)
        main_layout.addWidget(self.results_text_edit)

        self.clear_log_btn = QPushButton("Clear Log")
        self.clear_log_btn.clicked.connect(self.results_text_edit.clear)
        main_layout.addWidget(self.clear_log_btn, alignment=Qt.AlignmentFlag.AlignRight)

        main_layout.addWidget(QLabel("ROMs found:"))
        self.found_roms_tree_widget = QTreeWidget()
        self.found_roms_tree_widget.setHeaderLabels(["File Path", "ROM Name (Source)", "Source DAT File"])
        self.found_roms_tree_widget.setColumnWidth(0, 400)
        self.found_roms_tree_widget.setColumnWidth(1, 300)
        self.found_roms_tree_widget.setColumnWidth(2, 300)
        self.found_roms_tree_widget.doubleClicked.connect(self.openDirectory)
        main_layout.addWidget(self.found_roms_tree_widget)

        self.tabs.addTab(main_tab, "Main")

        info_tab = QWidget()
        info_layout = QVBoxLayout(info_tab)
        info_text = QTextEdit()
        info_text.setReadOnly(True)
        info_text.setPlainText(
            "Usage:\n\n" 
            "1) Select or drag-and-drop a single ROM file or a folder containing ROMs.\n"
            "2) If you choose a folder, you can enable 'Analyze recursively' to search subfolders.\n"
            "3) Click 'Start Analysis' to compute MD5/SHA1 hashes and compare against the DAT database.\n\n"
            "Notes:\n"
            "- You can add your own DAT files to the 'hashs' folder.\n"
            "- Supported extensions are read from 'extensions.txt' (one per line). If you add DAT files with other extensions, update 'extensions.txt' with those extensions.\n"
        )
        info_layout.addWidget(info_text)
        self.tabs.addTab(info_tab, "Info")

    def browse_path(self):
        dialog = QFileDialog(self)
        dialog.setFileMode(QFileDialog.FileMode.AnyFile)
        if dialog.exec():
            selected_path = dialog.selectedFiles()[0]
            self.path_line_edit.setText(selected_path)

    def browse_folder(self):
        dialog = QFileDialog(self)
        dialog.setFileMode(QFileDialog.FileMode.Directory)
        dialog.setOption(QFileDialog.Option.ShowDirsOnly, True)
        if dialog.exec():
            selected_path = dialog.selectedFiles()[0]
            self.path_line_edit.setText(selected_path)

    def start_analysis(self):
        path = self.path_line_edit.text().strip()
        if not path:
            QMessageBox.warning(self, "Error", "Please select a file or folder.")
            return
        if not os.path.exists(path):
            QMessageBox.warning(self, "Error", "The specified path does not exist.")
            return

        self.set_ui_enabled(False)
        self.progress_bar.setValue(0)
        self.results_text_edit.clear()

        recursive = self.recursive_checkbox.isChecked() if os.path.isdir(path) else False
        
        self.hash_thread = HashCheckThread(path, recursive, self.hash_database)
        self.hash_thread.progress.connect(self.progress_bar.setValue)
        self.hash_thread.log_message.connect(self.append_log_message)
        self.hash_thread.found_roms.connect(self.add_found_rom)
        self.hash_thread.finished.connect(lambda: self.set_ui_enabled(True))
        self.hash_thread.start()

    def set_ui_enabled(self, enabled: bool):
        self.path_line_edit.setEnabled(enabled)
        self.browse_file_btn.setEnabled(enabled)
        self.browse_folder_btn.setEnabled(enabled)
        self.start_analysis_btn.setEnabled(enabled)
        self.recursive_checkbox.setEnabled(enabled)
        self.start_analysis_btn.setText("🚀 Start Analysis" if enabled else "Analyzing...")

    def append_log_message(self, message: str):
        self.results_text_edit.appendPlainText(message)

    def add_found_rom(self, info: Dict[str, str]):
        item = QTreeWidgetItem([info['file'], info['name'], info['source']])
        self.found_roms_tree_widget.addTopLevelItem(item)

    def openDirectory(self):
        item = self.found_roms_tree_widget.currentItem()
        if item:
            file_path = item.text(0)
            base_path = Path(self.path_line_edit.text().strip())
            if base_path.is_file():
                full_path = base_path
            else:
                full_path = base_path.parent / file_path

            directory = os.path.dirname(full_path)
            if os.path.exists(directory):
                os.startfile(directory)

    def closeEvent(self, event):
        if self.hash_thread and self.hash_thread.isRunning():
            reply = QMessageBox.question(
                self, "Confirmation",
                "An analysis is in progress. Are you sure you want to quit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                event.ignore()
                return

        event.accept()

class PathLineEdit(QLineEdit):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event):
        mime = event.mimeData()
        if mime.hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dropEvent(self, event):
        mime = event.mimeData()
        if mime.hasUrls():
            url = mime.urls()[0]
            path = url.toLocalFile()
            if path:
                self.setText(path)
        else:
            super().dropEvent(event)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.showMaximized()
    sys.exit(app.exec())