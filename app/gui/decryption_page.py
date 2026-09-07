from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QFrame,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QRadioButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core import app_service


class DecryptionWorker(QObject):
    """Run container inspection and authenticated decryption off the UI thread."""

    finished = Signal(object)
    failed = Signal(object)

    def __init__(self, source: str, destination_directory: str, password: str | None,
                 recovery_key: str | None):
        super().__init__()
        self.source = source
        self.destination_directory = destination_directory
        self.password = password
        self.recovery_key = recovery_key

    def run(self) -> None:
        try:
            info = app_service.inspect_container(self.source)
            output = Path(self.destination_directory) / info.original_name
            if output.exists():
                raise ValueError("The restore destination already contains an item with this name.")

            if info.source_type == app_service.FILE_TYPE:
                result = app_service.decrypt_file(
                    self.source, output, password=self.password,
                    recovery_key=self.recovery_key,
                )
            else:
                result = app_service.decrypt_folder(
                    self.source, output, password=self.password,
                    recovery_key=self.recovery_key,
                )
            self.finished.emit(result)
        except Exception as exc:
            self.failed.emit(app_service.safe_error(exc))


class DecryptionPage(QWidget):
    def __init__(self):
        super().__init__()

        self.selected_file = ""
        self.method = "password"
        self._busy = False
        self._thread: QThread | None = None
        self._worker: DecryptionWorker | None = None

        self._build_ui()

    # ---------------------------------------------------------
    # UI
    # ---------------------------------------------------------

    def _build_ui(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        content = QWidget()
        layout = QVBoxLayout(content)

        layout.setContentsMargins(
            34, 28, 34, 35
        )
        layout.setSpacing(18)

        # Header
        header = QVBoxLayout()
        header.setSpacing(5)

        title = QLabel("Decryption")
        title.setObjectName("pageTitle")

        subtitle = QLabel(
            "Unlock your protected file or folder using "
            "a password or recovery key."
        )
        subtitle.setObjectName("pageSubtitle")

        header.addWidget(title)
        header.addWidget(subtitle)

        layout.addLayout(header)

        # Step 1
        layout.addWidget(
            self._file_card()
        )

        # Step 2
        layout.addWidget(
            self._authentication_card()
        )

        # Step 3
        layout.addWidget(
            self._destination_card()
        )

        # Bottom
        action = QFrame()
        action.setProperty("card", True)

        action_layout = QHBoxLayout(action)
        action_layout.setContentsMargins(
            18, 15, 18, 15
        )

        self.status = QLabel(
            "Ready — choose an encrypted file."
        )
        self.status.setObjectName(
            "statusText"
        )

        action_layout.addWidget(
            self.status
        )

        action_layout.addStretch()

        self.decrypt_button = QPushButton(
            "🔓   Decrypt Securely"
        )
        self.decrypt_button.setObjectName(
            "primaryButton"
        )
        self.decrypt_button.setMinimumHeight(46)
        self.decrypt_button.setMinimumWidth(220)
        self.decrypt_button.setCursor(
            Qt.PointingHandCursor
        )

        self.decrypt_button.clicked.connect(
            self._start_decryption
        )

        action_layout.addWidget(
            self.decrypt_button
        )

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setTextVisible(False)
        self.progress.setFixedWidth(130)
        action_layout.addWidget(self.progress)

        layout.addWidget(action)
        layout.addStretch()

        scroll.setWidget(content)

        root = QVBoxLayout(self)
        root.setContentsMargins(
            0, 0, 0, 0
        )
        root.addWidget(scroll)

    # ---------------------------------------------------------
    # Step Header
    # ---------------------------------------------------------

    def _header(
        self,
        number,
        title,
        hint,
    ):
        widget = QWidget()

        layout = QHBoxLayout(widget)
        layout.setContentsMargins(
            0, 0, 0, 8
        )
        layout.setSpacing(11)

        number_label = QLabel(
            number
        )
        number_label.setObjectName(
            "sectionNumber"
        )
        number_label.setAlignment(
            Qt.AlignCenter
        )

        texts = QVBoxLayout()
        texts.setContentsMargins(
            0, 0, 0, 0
        )
        texts.setSpacing(2)

        title_label = QLabel(title)
        title_label.setObjectName(
            "sectionTitle"
        )

        hint_label = QLabel(hint)
        hint_label.setObjectName(
            "sectionHint"
        )

        texts.addWidget(title_label)
        texts.addWidget(hint_label)

        layout.addWidget(number_label)
        layout.addLayout(texts)
        layout.addStretch()

        return widget

    # ---------------------------------------------------------
    # File
    # ---------------------------------------------------------

    def _file_card(self):
        card = QFrame()
        card.setProperty(
            "card",
            True,
        )

        layout = QVBoxLayout(card)
        layout.setContentsMargins(
            20, 18, 20, 20
        )

        layout.addWidget(
            self._header(
                "1",
                "Select encrypted data",
                "Choose a CipherForge encrypted file.",
            )
        )

        row = QHBoxLayout()
        row.setSpacing(10)

        self.file_field = QLineEdit()
        self.file_field.setReadOnly(True)
        self.file_field.setPlaceholderText(
            "No encrypted file selected"
        )

        choose = QPushButton(
            "Choose Encrypted File"
        )
        choose.setObjectName(
            "secondaryButton"
        )

        choose.clicked.connect(
            self._choose_file
        )

        row.addWidget(
            self.file_field,
            1,
        )
        row.addWidget(
            choose
        )

        layout.addLayout(row)

        return card

    # ---------------------------------------------------------
    # Authentication
    # ---------------------------------------------------------

    def _authentication_card(self):
        card = QFrame()
        card.setProperty(
            "card",
            True,
        )

        layout = QVBoxLayout(card)
        layout.setContentsMargins(
            20, 18, 20, 20
        )

        layout.addWidget(
            self._header(
                "2",
                "Choose unlock method",
                "Use either your password or your recovery key.",
            )
        )

        self.password_radio = QRadioButton(
            "Password"
        )

        self.recovery_radio = QRadioButton(
            "Recovery Key"
        )

        self.password_radio.setChecked(
            True
        )

        self.method_group = QButtonGroup(
            self
        )

        self.method_group.addButton(
            self.password_radio
        )
        self.method_group.addButton(
            self.recovery_radio
        )

        radio_row = QHBoxLayout()
        radio_row.setSpacing(25)

        radio_row.addWidget(
            self.password_radio
        )
        radio_row.addWidget(
            self.recovery_radio
        )
        radio_row.addStretch()

        layout.addLayout(
            radio_row
        )

        self.password_field = QLineEdit()
        self.password_field.setEchoMode(
            QLineEdit.Password
        )
        self.password_field.setPlaceholderText(
            "Enter your encryption password"
        )

        self.recovery_field = QLineEdit()
        self.recovery_field.setPlaceholderText(
            "Enter your recovery key"
        )

        layout.addWidget(
            self.password_field
        )

        self.recovery_field.hide()
        recovery_row = QHBoxLayout()
        recovery_row.addWidget(self.recovery_field, 1)
        self.recovery_file_button = QPushButton("Load Recovery File")
        self.recovery_file_button.setObjectName("secondaryButton")
        self.recovery_file_button.clicked.connect(self._load_recovery_file)
        self.recovery_file_button.hide()
        recovery_row.addWidget(self.recovery_file_button)
        layout.addLayout(recovery_row)

        self.password_radio.toggled.connect(
            self._change_method
        )

        return card

    def _change_method(self, password_selected):
        self.method = (
            "password"
            if password_selected
            else "recovery"
        )

        self.password_field.setVisible(
            password_selected
        )

        self.recovery_field.setVisible(
            not password_selected
        )
        self.recovery_file_button.setVisible(not password_selected)

    # ---------------------------------------------------------
    # Destination
    # ---------------------------------------------------------

    def _destination_card(self):
        card = QFrame()
        card.setProperty(
            "card",
            True,
        )

        layout = QVBoxLayout(card)
        layout.setContentsMargins(
            20, 18, 20, 20
        )

        layout.addWidget(
            self._header(
                "3",
                "Restore destination",
                "The decrypted content will be restored locally.",
            )
        )

        self.destination = QLineEdit()
        self.destination.setReadOnly(True)
        self.destination.setPlaceholderText(
            "Original location / selected destination"
        )

        browse = QPushButton(
            "Choose Destination"
        )
        browse.setObjectName(
            "secondaryButton"
        )

        browse.clicked.connect(
            self._choose_destination
        )

        row = QHBoxLayout()
        row.setSpacing(10)

        row.addWidget(
            self.destination,
            1,
        )
        row.addWidget(
            browse
        )

        layout.addLayout(row)

        return card

    # ---------------------------------------------------------
    # Actions
    # ---------------------------------------------------------

    def _choose_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select CipherForge encrypted file",
        )

        if path:
            self.selected_file = path
            self.file_field.setText(path)
            self.status.setText(
                "Encrypted file selected."
            )

    def _choose_destination(self):
        path = QFileDialog.getExistingDirectory(
            self,
            "Choose restore destination",
        )

        if path:
            self.destination.setText(
                path
            )

    def _load_recovery_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Load CipherForge recovery key", "",
            "CipherForge Recovery Key (*.cfrecovery);;All Files (*)",
        )
        if not path:
            return
        try:
            self.recovery_field.setText(app_service.load_recovery_key_file(path))
            self.status.setText("Recovery credential loaded.")
        except Exception as exc:
            QMessageBox.critical(
                self, "Recovery key unavailable", str(app_service.safe_error(exc)),
            )

    def _start_decryption(self):
        if self._busy:
            return
        if not self.selected_file:
            QMessageBox.warning(
                self,
                "Select encrypted file",
                "Please choose an encrypted file first.",
            )
            return

        if self.method == "password":
            if not self.password_field.text():
                QMessageBox.warning(
                    self,
                    "Password required",
                    "Enter the password to continue.",
                )
                return

        else:
            if not self.recovery_field.text():
                QMessageBox.warning(
                    self,
                    "Recovery key required",
                    "Enter the recovery key to continue.",
                )
                return

        destination = self.destination.text().strip()
        if not destination or not Path(destination).is_dir():
            QMessageBox.warning(
                self, "Destination required",
                "Choose an existing folder for the restored data.",
            )
            return

        password = self.password_field.text() if self.method == "password" else None
        recovery_key = self.recovery_field.text() if self.method == "recovery" else None
        self._busy = True
        self.decrypt_button.setEnabled(False)
        self.progress.setRange(0, 0)
        self.progress.setVisible(True)
        self.status.setText("Authenticating and restoring data…")

        self._thread = QThread(self)
        self._worker = DecryptionWorker(self.selected_file, destination, password, recovery_key)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._decryption_finished)
        self._worker.failed.connect(self._decryption_failed)
        self._worker.finished.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._thread.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread_finished)
        self._thread.start()

    def _decryption_finished(self, result):
        self._finish_busy()
        self.password_field.clear()
        self.recovery_field.clear()
        output = getattr(result, "output", "")
        self.status.setText("Decryption completed successfully.")
        QMessageBox.information(
            self, "Decryption complete",
            f"Your data was restored successfully.\n\nRestored output:\n{output}",
        )

    def _decryption_failed(self, error):
        self._finish_busy()
        message = str(error).strip() or "Decryption could not be completed."
        self.status.setText("Decryption failed.")
        QMessageBox.critical(self, "Decryption failed", message)

    def _finish_busy(self):
        self._busy = False
        self.decrypt_button.setEnabled(True)
        self.progress.setVisible(False)

    def _thread_finished(self):
        self._worker = None
        if self._thread is not None:
            self._thread.deleteLater()
        self._thread = None
