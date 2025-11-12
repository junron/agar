import os

from config import Config
import trie
import idautils
import ida_funcs
import ida_hexrays
import idaapi
import idc
import json
import agar.scripts.set_stdlib_funcproto as set_stdlib_funcproto
import agar.scripts.go_slicer as go_slicer
import agar.scripts.interface_detector as interface_detector
import agar.scripts.go_stringer as go_stringer
import agar.itab_parser

# Try to import Qt6 first, fall back to Qt5
try:
    from PySide6.QtWidgets import (
        QDialog, QVBoxLayout, 
        QGroupBox, QCheckBox, QPushButton, QHBoxLayout,
        QRadioButton, QLineEdit, QLabel, QProgressBar, QApplication
    )
    from PySide6.QtCore import  QTimer
    QT_VERSION = 6
except ImportError:
    from PyQt5.QtWidgets import (
        QDialog, QVBoxLayout, 
        QGroupBox, QCheckBox, QPushButton, QHBoxLayout,
        QRadioButton, QLineEdit, QLabel, QProgressBar, QApplication
    )
    from PyQt5.QtCore import QTimer
    QT_VERSION = 5

def get_all_functions() -> trie.PrefixTrie:
    t = trie.PrefixTrie()
    with open(os.path.join(os.path.dirname(__file__), "scripts", "types.json"), "r", encoding="utf-8") as f:
        builtin_functions = json.load(f)
    internal_packages = {"runtime_pprof", "embed", "html", "gopkg", "iter", "gogo", "golang", "type:"}
    for func in builtin_functions.keys():
        pkg = func.split(".")[0]
        internal_packages.add(pkg)

    x = set()
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        if func_name.split(".")[0] not in internal_packages:
            if not any(func_name.startswith(bad_prefix) for bad_prefix in ["go:", "internal_", "_rt", "debug", "crypto_internal"]):
                t.insert(func_name)
                x.add(func_name.split(".")[0])
    # print(x)
            
    return t

class AgarForm(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.c = Config()
        self.setWindowTitle("AGAR")
        self.setModal(True)
        self.resize(400, 300)
        self.functions = get_all_functions()
        self.func = ida_funcs.get_func(idc.here())
        if not self.func:
            self.show_error_form()
            return
        self.function_name = idc.get_name(self.func.start_ea)
        self.cancelled = False
        self.processing = False
        self.current_function_index = 0
        self.functions_to_process = []
        self.run_slice_rebuild = False
        self.run_interface_rebuild = False
        self.run_string_detection = False
        
        main_layout = QVBoxLayout(self)

        completed = " (Completed)"
        
        section1 = QGroupBox("")
        section1_layout = QVBoxLayout()
        self.run_functyper = QCheckBox("Set Go standard library function types" + (completed if self.c.has_set_functypes else ""))
        self.run_functyper.setChecked(not self.c.has_set_functypes)
        self.run_itab_parser = QCheckBox("Parse Go interface tables" + (completed if self.c.has_parsed_itabs else ""))
        self.run_itab_parser.setChecked(not self.c.has_parsed_itabs)
        section1_layout.addWidget(self.run_functyper)
        section1_layout.addWidget(self.run_itab_parser)
        section1.setLayout(section1_layout)
        main_layout.addWidget(section1)
        
        section2 = QGroupBox("String Detection")
        section2_layout = QVBoxLayout()
        self.enableSliceRebuild = QCheckBox("Rebuild slices")
        self.enableInterfaceRebuild = QCheckBox("Rebuild interfaces")
        self.enableStringDetection = QCheckBox("Detect strings")
        self.enableSliceRebuild.setChecked(True)
        self.enableInterfaceRebuild.setChecked(True)
        self.enableStringDetection.setChecked(True)
        section2_layout.addWidget(self.enableSliceRebuild)
        section2_layout.addWidget(self.enableInterfaceRebuild)
        section2_layout.addWidget(self.enableStringDetection)
        section2.setLayout(section2_layout)
        main_layout.addWidget(section2)
        
        self.run_functyper.toggled.connect(self.update_ok_button_state)
        self.enableSliceRebuild.toggled.connect(self.update_ok_button_state)
        self.enableInterfaceRebuild.toggled.connect(self.update_ok_button_state)
        self.enableStringDetection.toggled.connect(self.update_ok_button_state)
        
        section3 = QGroupBox("Scope")
        section3_layout = QVBoxLayout()
        self.scope_warning = QLabel("Warning: Functions in scope will be decompiled (probably multiple times) and thus take some time to complete. Please narrow your scope with the 'Functions starting with' option.")
        self.scope_warning.setWordWrap(True)
        self.scope_warning.setStyleSheet("QLabel { color: #b36b00; padding: 4px; }")
        self.scope_warning.setVisible(False)
        section3_layout.addWidget(self.scope_warning)
        self.radioButtonCurrentFunction = QRadioButton("Current function")
        self.radioButtonAllFunctions = QRadioButton(f"All functions ({self.functions.size} functions)")
        self.radioButtonFunctionPrefixFilter = QRadioButton("Functions starting with")
        self.func_prefix = QLineEdit()
        self.func_prefix.setPlaceholderText("Function name prefix")
        self.func_prefix.setText(self.function_name)
        
        self.func_prefix.setStyleSheet("QLineEdit { border: 1px solid #999; padding: 2px; }")
        
        self.radioButtonCurrentFunction.setChecked(True)
        self.radioButtonAllFunctions.toggled.connect(self.scope_warning.setVisible)

        section3_layout.addWidget(self.radioButtonCurrentFunction)
        section3_layout.addWidget(self.radioButtonAllFunctions)
        section3_layout.addWidget(self.radioButtonFunctionPrefixFilter)
        
        text_field_layout = QHBoxLayout()
        text_field_layout.addWidget(self.func_prefix)
        
        self.func_count_label = QLabel("(0)")
        text_field_layout.addWidget(self.func_count_label)
        
        section3_layout.addLayout(text_field_layout)
        
        self.func_prefix.textChanged.connect(self.update_func_count)
        self.update_func_count()
        
        section3.setLayout(section3_layout)
        main_layout.addWidget(section3)
        
        main_layout.addStretch()
        
        # Add progress bar (initially hidden)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setTextVisible(True)
        main_layout.addWidget(self.progress_bar)
        
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        self.ok_button = QPushButton("OK")
        self.cancel_button = QPushButton("Cancel")
        self.close_button = QPushButton("Close")
        self.close_button.setVisible(False)
        self.ok_button.clicked.connect(self.on_ok_clicked)
        self.cancel_button.clicked.connect(self.on_cancel_clicked)
        self.close_button.clicked.connect(self.reject)
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.close_button)
        main_layout.addLayout(button_layout)
        
        self.update_ok_button_state()

    def show_error_form(self):
        layout = QVBoxLayout(self)
        
        message_label = QLabel("⚠️ Please place the cursor inside a function to use AGAR.")
        message_label.setWordWrap(True)
        message_label.setStyleSheet("QLabel { padding: 20px; font-size: 11pt; }")
        layout.addWidget(message_label)
        
        layout.addStretch()
        
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.reject)
        ok_button.setDefault(True)
        button_layout.addWidget(ok_button)
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        self.resize(350, 150)

    def on_ok_clicked(self):
        self.ok_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.processing_complete = False

        self.progress_bar.setMaximum(len(self.functions_to_process) if self.functions_to_process else 1)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Waiting for auto-analysis...")
        QApplication.processEvents()
        
        if self.run_functyper.isChecked():
            print("[AGAR] Setting Go standard library function types...")
            set_stdlib_funcproto.main()
            self.c.has_set_functypes = True
            idaapi.auto_wait()
            QApplication.processEvents()
        
        if self.run_itab_parser.isChecked():
            print("[AGAR] Parsing Go interface tables and updating typedefs...")
            agar.itab_parser.parse_all_itabs(yap=False)
            self.c.has_parsed_itabs = True
            idaapi.auto_wait()
            QApplication.processEvents()

        self.run_slice_rebuild = self.enableSliceRebuild.isChecked()
        self.run_interface_rebuild = self.enableInterfaceRebuild.isChecked()
        self.run_string_detection = self.enableStringDetection.isChecked()

        if not (self.run_slice_rebuild or self.run_interface_rebuild or self.run_string_detection):
            self.complete_processing()
            return None

        if self.radioButtonCurrentFunction.isChecked():
            functions = [self.function_name]
        elif self.radioButtonAllFunctions.isChecked():
            functions = self.functions.search("")
        elif self.radioButtonFunctionPrefixFilter.isChecked():
            functions = self.functions.search(self.func_prefix.text())

        self.functions_to_process = functions
        self.current_function_index = 0
        self.processing = True
        self.cancelled = False

        self.update_progress(0, len(self.functions_to_process))
        
        QTimer.singleShot(0, self.process_next_function)

    def process_next_function(self):
        if self.cancelled:
            self.on_processing_cancelled()
            return
        
        if self.current_function_index >= len(self.functions_to_process):
            self.complete_processing()
            return
        
        func_name = self.functions_to_process[self.current_function_index]
        print(f"[AGAR] Processing function: {func_name}")
        
        func = ida_hexrays.decompile(idc.get_name_ea_simple(func_name), flags=ida_hexrays.DECOMP_NO_CACHE)
        decompilation_failed = False
        if func is None:
            decompilation_failed = True
        if not decompilation_failed and self.run_interface_rebuild:
            interface_detector.apply_interface_detector(func, yap=False)
        if not decompilation_failed and self.run_slice_rebuild:
            func = ida_hexrays.decompile(func.entry_ea, flags=ida_hexrays.DECOMP_NO_CACHE)
            if func is not None:
                go_slicer.apply_slice_builder(func, yap=False)
            else:
                decompilation_failed = True
        if not decompilation_failed and self.run_string_detection:
            func = ida_hexrays.decompile(func.entry_ea, flags=ida_hexrays.DECOMP_NO_CACHE)
            if func is not None:
                go_stringer.apply_go_stringer(func, yap=False)
            else:
                decompilation_failed = True
        
        if decompilation_failed:
            print(f"[AGAR] Warning: Could not decompile function {func_name}, skipping.")

        self.current_function_index += 1
        self.update_progress(self.current_function_index, len(self.functions_to_process))
        
        QApplication.processEvents()
        
        QTimer.singleShot(0, self.process_next_function)

    def on_cancel_clicked(self):
        self.cancelled = True
        print("[AGAR] Cancelling...")
        if self.processing:
            self.cancel_button.setEnabled(False)
            self.cancel_button.setText("Cancelling...")
        else:
            self.reject()

    def on_processing_cancelled(self):
        """Called when processing is cancelled."""
        self.processing = False
        self.progress_bar.setFormat("Cancelled")
        self.ok_button.setVisible(False)
        self.cancel_button.setVisible(False)
        self.close_button.setVisible(True)

    def update_progress(self, current, total):
        """Update the progress bar."""
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        self.progress_bar.setFormat(f"{current}/{total} - %p%")

    def complete_processing(self):
        """Called when all processing is complete."""
        self.processing_complete = True
        self.processing = False
        self.ok_button.setVisible(False)
        self.cancel_button.setVisible(False)
        self.close_button.setVisible(True)
        self.progress_bar.setValue(self.progress_bar.maximum())
        self.progress_bar.setFormat("Complete!")

    def update_ok_button_state(self):
        any_checked = (
            self.run_functyper.isChecked() or
            self.enableSliceRebuild.isChecked() or
            self.enableInterfaceRebuild.isChecked() or
            self.enableStringDetection.isChecked()
        )
        self.ok_button.setEnabled(any_checked)

    def update_func_count(self):
        func_count = len(self.functions.search(self.func_prefix.text()))
        self.func_count_label.setText(f"({func_count})")
        if self.func_prefix.hasFocus() and not self.radioButtonFunctionPrefixFilter.isChecked():
            self.radioButtonFunctionPrefixFilter.setChecked(True)


def show_form():
    form = AgarForm()
    form.exec() if QT_VERSION == 6 else form.exec_()
