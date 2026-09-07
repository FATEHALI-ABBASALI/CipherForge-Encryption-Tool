from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import (
    QObject,
    Qt,
    QThread,
    Signal,
)
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core import app_service


class EncryptionWorker(QObject):
    """
    Background worker for CipherForge encryption.

    The worker never touches GUI widgets directly.
    """

    finished = Signal(object)
    failed = Signal(object)

    def __init__(
        self,
        source: str,
        source_type: str,
        destination: str,
        algorithm: str,
        password: str,
        recovery_storage: str,
        recovery_destination: str,
        recovery_filename: str | None,
        overwrite: bool,
    ):
        super().__init__()

        self.source = source
        self.source_type = source_type
        self.destination = destination
        self.algorithm = algorithm
        self.password = password
        self.recovery_storage = recovery_storage
        self.recovery_destination = recovery_destination
        self.recovery_filename = recovery_filename
        self.overwrite = overwrite

    def run(self) -> None:
        """
        Execute the selected encryption operation.
        """

        try:
            if self.source_type == "file":
                result = app_service.encrypt_file(
                    self.source,
                    self.destination,
                    algorithm=self.algorithm,
                    password=self.password,
                    recovery_storage=self.recovery_storage,
                    recovery_directory=self.recovery_destination,
                    recovery_filename=self.recovery_filename,
                    overwrite=self.overwrite,
                )

            elif self.source_type == "folder":
                result = app_service.encrypt_folder(
                    self.source,
                    self.destination,
                    algorithm=self.algorithm,
                    password=self.password,
                    recovery_storage=self.recovery_storage,
                    recovery_directory=self.recovery_destination,
                    recovery_filename=self.recovery_filename,
                    overwrite=self.overwrite,
                )

            else:
                raise ValueError(
                    "Unsupported encryption source type."
                )

            self.finished.emit(result)

        except Exception as exc:
            try:
                safe = app_service.safe_error(exc)
            except Exception:
                safe = exc

            self.failed.emit(safe)


class EncryptionPage(QWidget):
    """
    CipherForge encryption workspace.

    This page is responsible only for:
        - collecting user input
        - validating GUI state
        - starting background encryption
        - displaying safe results

    Cryptographic work is delegated to app_service.py.
    """

    def __init__(self):
        super().__init__()

        # -----------------------------------------------------
        # State
        # -----------------------------------------------------

        self.selected_path = ""
        self.selected_type = ""

        self.algorithm = "AES-256-GCM"

        self.recovery_destination_type = "local"
        self.recovery_destination_path = ""

        self.output_path = ""

        self._busy = False
        self._pending_overwrite = False

        self._thread: QThread | None = None
        self._worker: EncryptionWorker | None = None

        # -----------------------------------------------------
        # Widgets
        # -----------------------------------------------------

        self.selected_label: QLabel | None = None
        self.output_label: QLabel | None = None
        self.recovery_location: QLabel | None = None
        self.status_label: QLabel | None = None
        self.progress_label: QLabel | None = None

        self.password: QLineEdit | None = None
        self.confirm_password: QLineEdit | None = None

        self.password_strength: QLabel | None = None
        self.password_match: QLabel | None = None

        self.aes_radio: QRadioButton | None = None
        self.chacha_radio: QRadioButton | None = None
        self.algorithm_group: QButtonGroup | None = None

        self.local_recovery: QRadioButton | None = None
        self.usb_recovery: QRadioButton | None = None
        self.recovery_group: QButtonGroup | None = None

        self.local_recovery_card: QFrame | None = None
        self.usb_recovery_card: QFrame | None = None

        self.encrypt_button: QPushButton | None = None
        self.reset_button: QPushButton | None = None
        self.progress_bar: QProgressBar | None = None

        self.choose_output_button: QPushButton | None = None

        # -----------------------------------------------------
        # Build
        # -----------------------------------------------------

        self._build_ui()
        self._load_preferences()

    def _load_preferences(self) -> None:
        """Apply persisted non-secret defaults without blocking startup."""
        try:
            config = app_service.get_service_config()
        except Exception:
            return

        algorithm = config.get("algorithm")
        if algorithm == "chacha20-poly1305" and self.chacha_radio:
            self.chacha_radio.setChecked(True)
        elif algorithm == "aes-256-gcm" and self.aes_radio:
            self.aes_radio.setChecked(True)

        filename = config.get("recovery_filename")
        if isinstance(filename, str) and filename and self.recovery_filename:
            self.recovery_filename.setText(filename)

    # =========================================================
    # MAIN UI
    # =========================================================

    def _build_ui(self) -> None:
        scroll = QScrollArea()

        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarAlwaysOff
        )

        content = QWidget()

        layout = QVBoxLayout(content)

        layout.setContentsMargins(
            34,
            28,
            34,
            35,
        )

        layout.setSpacing(18)

        # -----------------------------------------------------
        # Header
        # -----------------------------------------------------

        header = QVBoxLayout()
        header.setSpacing(5)

        title = QLabel("Encryption")
        title.setObjectName("pageTitle")

        subtitle = QLabel(
            "Protect a file or an entire folder with "
            "authenticated encryption and a separate recovery key."
        )

        subtitle.setObjectName("pageSubtitle")
        subtitle.setWordWrap(True)

        header.addWidget(title)
        header.addWidget(subtitle)

        layout.addLayout(header)

        # -----------------------------------------------------
        # Security banner
        # -----------------------------------------------------

        layout.addWidget(
            self._create_security_banner()
        )

        # -----------------------------------------------------
        # Step 1
        # -----------------------------------------------------

        layout.addWidget(
            self._create_source_card()
        )

        # -----------------------------------------------------
        # Step 2
        # -----------------------------------------------------

        layout.addWidget(
            self._create_output_card()
        )

        # -----------------------------------------------------
        # Step 3
        # -----------------------------------------------------

        layout.addWidget(
            self._create_algorithm_card()
        )

        # -----------------------------------------------------
        # Step 4
        # -----------------------------------------------------

        layout.addWidget(
            self._create_password_card()
        )

        # -----------------------------------------------------
        # Step 5
        # -----------------------------------------------------

        layout.addWidget(
            self._create_recovery_card()
        )

        # -----------------------------------------------------
        # Action
        # -----------------------------------------------------

        layout.addWidget(
            self._create_action_card()
        )

        layout.addStretch()

        scroll.setWidget(content)

        root = QVBoxLayout(self)

        root.setContentsMargins(
            0,
            0,
            0,
            0,
        )

        root.addWidget(scroll)

    # =========================================================
    # SECURITY BANNER
    # =========================================================

    def _create_security_banner(self) -> QFrame:
        card = QFrame()
        card.setObjectName("recoveryInfo")

        layout = QHBoxLayout(card)

        layout.setContentsMargins(
            16,
            13,
            16,
            13,
        )

        layout.setSpacing(12)

        icon = QLabel("🛡️")
        icon.setObjectName("dropIcon")

        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)

        title = QLabel(
            "Secure encryption"
        )

        title.setObjectName(
            "algorithmName"
        )

        description = QLabel(
            "Your password protects the encryption key. "
            "A separate recovery key is stored at the location you choose."
        )

        description.setObjectName(
            "algorithmDescription"
        )

        description.setWordWrap(True)

        text_layout.addWidget(title)
        text_layout.addWidget(description)

        layout.addWidget(icon)
        layout.addLayout(text_layout, 1)

        return card

    # =========================================================
    # SECTION HEADER
    # =========================================================

    def _step_header(
        self,
        number: int,
        title: str,
        hint: str,
    ) -> QWidget:
        container = QWidget()

        layout = QHBoxLayout(container)

        layout.setContentsMargins(
            0,
            0,
            0,
            8,
        )

        layout.setSpacing(11)

        number_label = QLabel(
            str(number)
        )

        number_label.setObjectName(
            "sectionNumber"
        )

        number_label.setAlignment(
            Qt.AlignCenter
        )

        text_layout = QVBoxLayout()

        text_layout.setContentsMargins(
            0,
            0,
            0,
            0,
        )

        text_layout.setSpacing(2)

        title_label = QLabel(title)

        title_label.setObjectName(
            "sectionTitle"
        )

        hint_label = QLabel(hint)

        hint_label.setObjectName(
            "sectionHint"
        )

        hint_label.setWordWrap(True)

        text_layout.addWidget(title_label)
        text_layout.addWidget(hint_label)

        layout.addWidget(number_label)
        layout.addLayout(text_layout)
        layout.addStretch()

        return container

    # =========================================================
    # STEP 1 - SOURCE
    # =========================================================

    def _create_source_card(self) -> QFrame:
        card = QFrame()
        card.setProperty("card", True)

        layout = QVBoxLayout(card)

        layout.setContentsMargins(
            20,
            18,
            20,
            20,
        )

        layout.addWidget(
            self._step_header(
                1,
                "Choose what to protect",
                "Select one file or an entire folder.",
            )
        )

        drop_zone = QFrame()
        drop_zone.setObjectName("dropZone")
        drop_zone.setMinimumHeight(150)

        drop_layout = QVBoxLayout(drop_zone)

        drop_layout.setAlignment(Qt.AlignCenter)
        drop_layout.setSpacing(6)

        icon = QLabel("📁")
        icon.setObjectName("dropIcon")
        icon.setAlignment(Qt.AlignCenter)

        title = QLabel(
            "Select a file or folder"
        )

        title.setObjectName("dropTitle")
        title.setAlignment(Qt.AlignCenter)

        hint = QLabel(
            "CipherForge will create a protected .cforge container."
        )

        hint.setObjectName("dropHint")
        hint.setAlignment(Qt.AlignCenter)
        hint.setWordWrap(True)

        buttons = QHBoxLayout()
        buttons.setSpacing(10)

        file_button = QPushButton(
            "Choose File"
        )

        file_button.setObjectName(
            "secondaryButton"
        )

        folder_button = QPushButton(
            "Choose Folder"
        )

        folder_button.setObjectName(
            "secondaryButton"
        )

        file_button.setCursor(
            Qt.PointingHandCursor
        )

        folder_button.setCursor(
            Qt.PointingHandCursor
        )

        file_button.clicked.connect(
            self._choose_file
        )

        folder_button.clicked.connect(
            self._choose_folder
        )

        buttons.addStretch()
        buttons.addWidget(file_button)
        buttons.addWidget(folder_button)
        buttons.addStretch()

        drop_layout.addWidget(icon)
        drop_layout.addWidget(title)
        drop_layout.addWidget(hint)
        drop_layout.addSpacing(5)
        drop_layout.addLayout(buttons)

        layout.addWidget(drop_zone)

        self.selected_label = QLabel(
            "No file or folder selected."
        )

        self.selected_label.setObjectName(
            "statusText"
        )

        self.selected_label.setWordWrap(True)

        layout.addWidget(
            self.selected_label
        )

        return card

    # =========================================================
    # STEP 2 - OUTPUT
    # =========================================================

    def _create_output_card(self) -> QFrame:
        card = QFrame()
        card.setProperty("card", True)

        layout = QVBoxLayout(card)

        layout.setContentsMargins(
            20,
            18,
            20,
            20,
        )

        layout.addWidget(
            self._step_header(
                2,
                "Choose encrypted output",
                "By default CipherForge places the .cforge container beside the source.",
            )
        )

        row = QHBoxLayout()
        row.setSpacing(10)

        self.output_label = QLabel(
            "Default output location will be used."
        )

        self.output_label.setObjectName(
            "recoveryPath"
        )

        self.output_label.setWordWrap(True)

        self.choose_output_button = QPushButton(
            "Choose Output"
        )

        self.choose_output_button.setObjectName(
            "secondaryButton"
        )

        self.choose_output_button.setCursor(
            Qt.PointingHandCursor
        )

        self.choose_output_button.clicked.connect(
            self._choose_output
        )

        row.addWidget(
            self.output_label,
            1,
        )

        row.addWidget(
            self.choose_output_button
        )

        layout.addLayout(row)

        self.overwrite_checkbox = QCheckBox(
            "Allow replacing an existing encrypted output"
        )

        self.overwrite_checkbox.setObjectName(
            "fieldLabel"
        )

        layout.addWidget(
            self.overwrite_checkbox
        )

        return card

    # =========================================================
    # STEP 3 - ALGORITHM
    # =========================================================

    def _create_algorithm_card(self) -> QFrame:
        card = QFrame()
        card.setProperty("card", True)

        layout = QVBoxLayout(card)

        layout.setContentsMargins(
            20,
            18,
            20,
            20,
        )

        layout.addWidget(
            self._step_header(
                3,
                "Select encryption algorithm",
                "Both options provide authenticated encryption.",
            )
        )

        self.algorithm_group = QButtonGroup(self)
        self.algorithm_group.setExclusive(True)

        grid = QGridLayout()

        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)

        # -----------------------------------------------------
        # AES
        # -----------------------------------------------------

        self.aes_radio = QRadioButton(
            "AES-256-GCM"
        )

        self.aes_radio.setChecked(True)
        self.aes_radio.setProperty(
            "algorithm",
            "AES-256-GCM",
        )

        self.algorithm_group.addButton(
            self.aes_radio
        )

        aes_card = self._algorithm_option(
            self.aes_radio,
            "AES-256-GCM",
            "Widely used authenticated encryption with "
            "excellent general-purpose performance.",
            "RECOMMENDED",
        )

        # -----------------------------------------------------
        # ChaCha
        # -----------------------------------------------------

        self.chacha_radio = QRadioButton(
            "ChaCha20-Poly1305"
        )

        self.chacha_radio.setProperty(
            "algorithm",
            "ChaCha20-Poly1305",
        )

        self.algorithm_group.addButton(
            self.chacha_radio
        )

        chacha_card = self._algorithm_option(
            self.chacha_radio,
            "ChaCha20-Poly1305",
            "Modern authenticated encryption with "
            "strong software performance.",
            "ALTERNATIVE",
        )

        grid.addWidget(
            aes_card,
            0,
            0,
        )

        grid.addWidget(
            chacha_card,
            0,
            1,
        )

        layout.addLayout(grid)

        self.algorithm_group.buttonClicked.connect(
            self._algorithm_changed
        )

        self._update_algorithm_cards()

        return card

    def _algorithm_option(
        self,
        radio: QRadioButton,
        name: str,
        description: str,
        badge: str,
    ) -> QFrame:
        card = QFrame()

        card.setObjectName(
            "algorithmCard"
        )

        card.setProperty(
            "selected",
            radio.isChecked(),
        )

        card.setMinimumHeight(115)
        card.setCursor(Qt.PointingHandCursor)

        layout = QHBoxLayout(card)

        layout.setContentsMargins(
            15,
            12,
            15,
            12,
        )

        layout.setSpacing(10)

        layout.addWidget(radio)

        text_layout = QVBoxLayout()

        text_layout.setContentsMargins(
            0,
            0,
            0,
            0,
        )

        text_layout.setSpacing(3)

        name_label = QLabel(name)
        name_label.setObjectName(
            "algorithmName"
        )

        description_label = QLabel(
            description
        )

        description_label.setObjectName(
            "algorithmDescription"
        )

        description_label.setWordWrap(True)

        badge_label = QLabel(badge)
        badge_label.setObjectName(
            "algorithmBadge"
        )

        text_layout.addWidget(name_label)
        text_layout.addWidget(description_label)
        text_layout.addWidget(badge_label)

        layout.addLayout(text_layout)
        layout.addStretch()

        radio._algorithm_card = card

        def select_card(_event):
            radio.setChecked(True)
            self._algorithm_changed(radio)

        card.mousePressEvent = select_card

        return card

    def _algorithm_changed(
        self,
        button: QRadioButton,
    ) -> None:
        if button is None:
            return

        algorithm = button.property(
            "algorithm"
        )

        if not algorithm:
            return

        self.algorithm = str(
            algorithm
        )

        self._update_algorithm_cards()

        if self.status_label:
            self.status_label.setText(
                f"Algorithm selected: {self.algorithm}"
            )

    def _update_algorithm_cards(self) -> None:
        if not self.aes_radio:
            return

        if not self.chacha_radio:
            return

        for radio in (
            self.aes_radio,
            self.chacha_radio,
        ):
            card = getattr(
                radio,
                "_algorithm_card",
                None,
            )

            if card is None:
                continue

            card.setProperty(
                "selected",
                radio.isChecked(),
            )

            card.style().unpolish(card)
            card.style().polish(card)
            card.update()

    # =========================================================
    # STEP 4 - PASSWORD
    # =========================================================

    def _create_password_card(self) -> QFrame:
        card = QFrame()
        card.setProperty("card", True)

        layout = QVBoxLayout(card)

        layout.setContentsMargins(
            20,
            18,
            20,
            20,
        )

        layout.addWidget(
            self._step_header(
                4,
                "Create your protection",
                "Use a strong password. You will need it to decrypt the data.",
            )
        )

        grid = QGridLayout()

        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(8)

        password_label = QLabel(
            "Password"
        )

        password_label.setObjectName(
            "fieldLabel"
        )

        confirm_label = QLabel(
            "Confirm password"
        )

        confirm_label.setObjectName(
            "fieldLabel"
        )

        self.password = QLineEdit()

        self.password.setEchoMode(
            QLineEdit.Password
        )

        self.password.setPlaceholderText(
            "Enter a strong password"
        )

        self.confirm_password = QLineEdit()

        self.confirm_password.setEchoMode(
            QLineEdit.Password
        )

        self.confirm_password.setPlaceholderText(
            "Re-enter your password"
        )

        self.password.textChanged.connect(
            self._password_changed
        )

        self.confirm_password.textChanged.connect(
            self._password_confirmation_changed
        )

        grid.addWidget(
            password_label,
            0,
            0,
        )

        grid.addWidget(
            confirm_label,
            0,
            1,
        )

        grid.addWidget(
            self.password,
            1,
            0,
        )

        grid.addWidget(
            self.confirm_password,
            1,
            1,
        )

        layout.addLayout(grid)

        # -----------------------------------------------------
        # Show password
        # -----------------------------------------------------

        show_row = QHBoxLayout()

        show_password = QCheckBox(
            "Show passwords"
        )

        show_password.setObjectName(
            "fieldLabel"
        )

        show_password.toggled.connect(
            self._toggle_password_visibility
        )

        show_row.addWidget(
            show_password
        )

        show_row.addStretch()

        layout.addLayout(show_row)

        # -----------------------------------------------------
        # Strength
        # -----------------------------------------------------

        self.password_strength = QLabel(
            "Password strength: —"
        )

        self.password_strength.setObjectName(
            "statusText"
        )

        layout.addWidget(
            self.password_strength
        )

        self.password_match = QLabel(
            ""
        )

        self.password_match.setObjectName(
            "statusText"
        )

        layout.addWidget(
            self.password_match
        )

        return card

    def _toggle_password_visibility(
        self,
        visible: bool,
    ) -> None:
        mode = (
            QLineEdit.Normal
            if visible
            else QLineEdit.Password
        )

        if self.password:
            self.password.setEchoMode(mode)

        if self.confirm_password:
            self.confirm_password.setEchoMode(mode)

    def _password_changed(
        self,
        text: str,
    ) -> None:
        length = len(text)

        has_upper = any(
            char.isupper()
            for char in text
        )

        has_lower = any(
            char.islower()
            for char in text
        )

        has_digit = any(
            char.isdigit()
            for char in text
        )

        has_symbol = any(
            not char.isalnum()
            for char in text
        )

        score = 0

        if length >= 8:
            score += 1

        if length >= 12:
            score += 1

        if length >= 16:
            score += 1

        if has_upper and has_lower:
            score += 1

        if has_digit:
            score += 1

        if has_symbol:
            score += 1

        if length == 0:
            strength = "Password strength: —"

        elif score <= 2:
            strength = "Password strength: Weak"

        elif score <= 4:
            strength = "Password strength: Moderate"

        elif score == 5:
            strength = "Password strength: Strong"

        else:
            strength = "Password strength: Very strong"

        if self.password_strength:
            self.password_strength.setText(
                strength
            )

        self._password_confirmation_changed(
            self.confirm_password.text()
            if self.confirm_password
            else ""
        )

    def _password_confirmation_changed(
        self,
        _text: str,
    ) -> None:
        if not self.password_match:
            return

        password = (
            self.password.text()
            if self.password
            else ""
        )

        confirmation = (
            self.confirm_password.text()
            if self.confirm_password
            else ""
        )

        if not confirmation:
            self.password_match.setText("")
            return

        if password == confirmation:
            self.password_match.setText(
                "✓ Passwords match."
            )
        else:
            self.password_match.setText(
                "✕ Passwords do not match."
            )

    # =========================================================
    # STEP 5 - RECOVERY
    # =========================================================

    def _create_recovery_card(self) -> QFrame:
        card = QFrame()
        card.setProperty("card", True)

        layout = QVBoxLayout(card)

        layout.setContentsMargins(
            20,
            18,
            20,
            20,
        )

        layout.setSpacing(12)

        layout.addWidget(
            self._step_header(
                5,
                "Recovery key",
                "A separate recovery key is generated automatically and saved separately.",
            )
        )

        info = QFrame()
        info.setObjectName("recoveryInfo")

        info_layout = QVBoxLayout(info)

        info_layout.setContentsMargins(
            15,
            12,
            15,
            12,
        )

        info_layout.setSpacing(4)

        info_title = QLabel(
            "🔑  Keep your recovery key safe"
        )

        info_title.setObjectName(
            "algorithmName"
        )

        info_text = QLabel(
            "The recovery key provides another way to unlock "
            "your encrypted data if the password is forgotten. "
            "Anyone who obtains it may be able to decrypt the data."
        )

        info_text.setObjectName(
            "algorithmDescription"
        )

        info_text.setWordWrap(True)

        info_layout.addWidget(info_title)
        info_layout.addWidget(info_text)

        layout.addWidget(info)

        destination_label = QLabel(
            "Recovery key storage"
        )

        destination_label.setObjectName(
            "fieldLabel"
        )

        layout.addWidget(
            destination_label
        )

        self.recovery_group = QButtonGroup(self)
        self.recovery_group.setExclusive(True)

        row = QHBoxLayout()
        row.setSpacing(12)

        # -----------------------------------------------------
        # Local
        # -----------------------------------------------------

        self.local_recovery = QRadioButton(
            "💻   Local PC"
        )

        self.local_recovery.setChecked(True)

        self.recovery_group.addButton(
            self.local_recovery
        )

        self.local_recovery_card = (
            self._recovery_destination(
                self.local_recovery,
                "Local PC",
                "Save the recovery key in a folder on this computer.",
            )
        )

        # -----------------------------------------------------
        # USB
        # -----------------------------------------------------

        self.usb_recovery = QRadioButton(
            "🔌   USB / External Drive"
        )

        self.recovery_group.addButton(
            self.usb_recovery
        )

        self.usb_recovery_card = (
            self._recovery_destination(
                self.usb_recovery,
                "USB / External Drive",
                "Save the recovery key on removable storage.",
            )
        )

        row.addWidget(
            self.local_recovery_card,
            1,
        )

        row.addWidget(
            self.usb_recovery_card,
            1,
        )

        layout.addLayout(row)

        # -----------------------------------------------------
        # Path
        # -----------------------------------------------------

        self.recovery_location = QLabel(
            "📁  Choose a recovery-key folder before encryption."
        )

        self.recovery_location.setObjectName(
            "recoveryPath"
        )

        self.recovery_location.setWordWrap(True)

        layout.addWidget(
            self.recovery_location
        )

        # -----------------------------------------------------
        # Filename
        # -----------------------------------------------------

        filename_row = QHBoxLayout()
        filename_row.setSpacing(10)

        filename_label = QLabel(
            "Recovery filename"
        )

        filename_label.setObjectName(
            "fieldLabel"
        )

        self.recovery_filename = QLineEdit()

        self.recovery_filename.setText(
            "CipherForge_Recovery_Key.cfrecovery"
        )

        self.recovery_filename.setPlaceholderText(
            "CipherForge_Recovery_Key.cfrecovery"
        )

        filename_row.addWidget(
            filename_label
        )

        filename_row.addWidget(
            self.recovery_filename,
            1,
        )

        layout.addLayout(
            filename_row
        )

        # -----------------------------------------------------
        # Signals
        # -----------------------------------------------------

        self.local_recovery.toggled.connect(
            self._local_recovery_toggled
        )

        self.usb_recovery.toggled.connect(
            self._usb_recovery_toggled
        )

        return card

    def _recovery_destination(
        self,
        radio: QRadioButton,
        title: str,
        description: str,
    ) -> QFrame:
        card = QFrame()

        card.setObjectName(
            "recoveryDestinationCard"
        )

        card.setProperty(
            "selected",
            radio.isChecked(),
        )

        card.setMinimumHeight(105)
        card.setCursor(Qt.PointingHandCursor)

        layout = QVBoxLayout(card)

        layout.setContentsMargins(
            15,
            13,
            15,
            13,
        )

        layout.setSpacing(5)

        layout.addWidget(radio)

        text = QLabel(description)

        text.setObjectName(
            "algorithmDescription"
        )

        text.setWordWrap(True)

        layout.addWidget(text)

        radio._recovery_card = card

        def select_card(_event):
            if radio == self.local_recovery:
                self._select_recovery_destination(
                    "local"
                )
            else:
                self._select_recovery_destination(
                    "usb"
                )

        card.mousePressEvent = select_card

        return card

    def _local_recovery_toggled(
        self,
        checked: bool,
    ) -> None:
        if not checked:
            return

        self._select_recovery_destination(
            "local"
        )

    def _usb_recovery_toggled(
        self,
        checked: bool,
    ) -> None:
        if not checked:
            return

        self._select_recovery_destination(
            "usb"
        )

    def _select_recovery_destination(
        self,
        destination: str,
    ) -> None:
        previous_type = (
            self.recovery_destination_type
        )

        previous_path = (
            self.recovery_destination_path
        )

        if destination == "local":
            folder = QFileDialog.getExistingDirectory(
                self,
                "Choose recovery-key folder",
            )

            if not folder:
                self._restore_recovery_selection(
                    previous_type,
                    previous_path,
                )
                return

            self.recovery_destination_type = "local"
            self.recovery_destination_path = folder

            if self.recovery_location:
                self.recovery_location.setText(
                    "💻  Recovery key folder:\n"
                    f"{folder}"
                )

            if self.status_label:
                self.status_label.setText(
                    "Local recovery-key folder selected."
                )

        elif destination == "usb":
            folder = QFileDialog.getExistingDirectory(
                self,
                "Choose USB / external-drive recovery folder",
            )

            if not folder:
                self._restore_recovery_selection(
                    previous_type,
                    previous_path,
                )
                return

            self.recovery_destination_type = "usb"
            self.recovery_destination_path = folder

            if self.recovery_location:
                self.recovery_location.setText(
                    "🔌  USB / external recovery-key folder:\n"
                    f"{folder}"
                )

            if self.status_label:
                self.status_label.setText(
                    "USB recovery-key folder selected."
                )

        self._update_recovery_cards()

    def _restore_recovery_selection(
        self,
        destination_type: str,
        destination_path: str,
    ) -> None:
        self.recovery_destination_type = (
            destination_type
        )

        self.recovery_destination_path = (
            destination_path
        )

        if self.local_recovery:
            self.local_recovery.blockSignals(True)
            self.local_recovery.setChecked(
                destination_type == "local"
            )
            self.local_recovery.blockSignals(False)

        if self.usb_recovery:
            self.usb_recovery.blockSignals(True)
            self.usb_recovery.setChecked(
                destination_type == "usb"
            )
            self.usb_recovery.blockSignals(False)

        if self.recovery_location:
            if destination_path:
                icon = (
                    "💻"
                    if destination_type == "local"
                    else "🔌"
                )

                self.recovery_location.setText(
                    f"{icon}  Recovery key folder:\n"
                    f"{destination_path}"
                )
            else:
                self.recovery_location.setText(
                    "📁  Choose a recovery-key folder "
                    "before encryption."
                )

        self._update_recovery_cards()

    def _update_recovery_cards(self) -> None:
        cards = (
            (
                self.local_recovery,
                self.local_recovery_card,
            ),
            (
                self.usb_recovery,
                self.usb_recovery_card,
            ),
        )

        for radio, card in cards:
            if radio is None or card is None:
                continue

            card.setProperty(
                "selected",
                radio.isChecked(),
            )

            card.style().unpolish(card)
            card.style().polish(card)
            card.update()

    # =========================================================
    # ACTION CARD
    # =========================================================

    def _create_action_card(self) -> QFrame:
        card = QFrame()
        card.setProperty("card", True)

        layout = QVBoxLayout(card)

        layout.setContentsMargins(
            18,
            15,
            18,
            15,
        )

        layout.setSpacing(10)

        # -----------------------------------------------------
        # Status row
        # -----------------------------------------------------

        status_row = QHBoxLayout()
        status_row.setSpacing(10)

        self.status_label = QLabel(
            "Ready — select a file or folder to begin."
        )

        self.status_label.setObjectName(
            "statusText"
        )

        self.status_label.setWordWrap(True)

        status_row.addWidget(
            self.status_label,
            1,
        )

        self.progress_label = QLabel(
            ""
        )

        self.progress_label.setObjectName(
            "statusText"
        )

        status_row.addWidget(
            self.progress_label
        )

        layout.addLayout(status_row)

        # -----------------------------------------------------
        # Progress
        # -----------------------------------------------------

        self.progress_bar = QProgressBar()

        self.progress_bar.setTextVisible(False)
        self.progress_bar.setMinimumHeight(7)
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)

        layout.addWidget(
            self.progress_bar
        )

        # -----------------------------------------------------
        # Buttons
        # -----------------------------------------------------

        buttons = QHBoxLayout()

        buttons.setSpacing(10)

        self.reset_button = QPushButton(
            "Reset"
        )

        self.reset_button.setObjectName(
            "secondaryButton"
        )

        self.reset_button.setMinimumHeight(46)
        self.reset_button.setCursor(
            Qt.PointingHandCursor
        )

        self.reset_button.clicked.connect(
            self.reset_form
        )

        self.encrypt_button = QPushButton(
            "🔒   Encrypt Securely"
        )

        self.encrypt_button.setObjectName(
            "primaryButton"
        )

        self.encrypt_button.setMinimumWidth(220)
        self.encrypt_button.setMinimumHeight(46)
        self.encrypt_button.setCursor(
            Qt.PointingHandCursor
        )

        self.encrypt_button.clicked.connect(
            self._start_encryption
        )

        buttons.addStretch()
        buttons.addWidget(
            self.reset_button
        )
        buttons.addWidget(
            self.encrypt_button
        )

        layout.addLayout(buttons)

        return card

    # =========================================================
    # SOURCE SELECTION
    # =========================================================

    def _choose_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select file to encrypt",
        )

        if not path:
            return

        self._set_source(
            path,
            "file",
        )

    def _choose_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(
            self,
            "Select folder to encrypt",
        )

        if not path:
            return

        self._set_source(
            path,
            "folder",
        )

    def _set_source(
        self,
        path: str,
        source_type: str,
    ) -> None:
        self.selected_path = path
        self.selected_type = source_type

        self.output_path = ""

        self._update_source_label()
        self._update_default_output()

        if self.status_label:
            self.status_label.setText(
                "Source selected — complete the security settings."
            )

    def _update_source_label(self) -> None:
        if not self.selected_label:
            return

        if not self.selected_path:
            self.selected_label.setText(
                "No file or folder selected."
            )
            return

        icon = (
            "📄"
            if self.selected_type == "file"
            else "📁"
        )

        source_name = Path(
            self.selected_path
        ).name

        self.selected_label.setText(
            f"{icon}  {source_name}\n"
            f"{self.selected_path}"
        )

    # =========================================================
    # OUTPUT
    # =========================================================

    def _default_output_path(self) -> str:
        if not self.selected_path:
            return ""

        source = Path(
            self.selected_path
        )

        if self.selected_type == "file":
            return str(
                source.with_suffix(
                    source.suffix + ".cforge"
                )
            )

        return str(
            source.parent
            / f"{source.name}.cforge"
        )

    def _update_default_output(self) -> None:
        if self.output_path:
            return

        default_path = self._default_output_path()

        if self.output_label:
            if default_path:
                self.output_label.setText(
                    "📦  Default encrypted output:\n"
                    f"{default_path}"
                )
            else:
                self.output_label.setText(
                    "Default output location will be used."
                )

    def _choose_output(self) -> None:
        if not self.selected_path:
            QMessageBox.information(
                self,
                "Choose source first",
                "Select the file or folder you want to encrypt first.",
            )
            return

        default_path = self._default_output_path()

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Choose encrypted output",
            default_path,
            "CipherForge Container (*.cforge);;"
            "All Files (*)",
        )

        if not path:
            return

        if not path.lower().endswith(
            ".cforge"
        ):
            path += ".cforge"

        self.output_path = path

        if self.output_label:
            self.output_label.setText(
                "📦  Encrypted output:\n"
                f"{path}"
            )

        if self.status_label:
            self.status_label.setText(
                "Custom encrypted output selected."
            )

    def _effective_output_path(self) -> str:
        if self.output_path:
            return self.output_path

        return self._default_output_path()

    # =========================================================
    # VALIDATION
    # =========================================================

    def _validate_form(self) -> bool:
        # -----------------------------------------------------
        # Source
        # -----------------------------------------------------

        if not self.selected_path:
            QMessageBox.warning(
                self,
                "Select data",
                "Please choose a file or folder first.",
            )
            return False

        source = Path(
            self.selected_path
        )

        if not source.exists():
            QMessageBox.warning(
                self,
                "Source unavailable",
                "The selected file or folder no longer exists.",
            )
            return False

        if self.selected_type == "file":
            if not source.is_file():
                QMessageBox.warning(
                    self,
                    "Invalid source",
                    "The selected path is no longer a file.",
                )
                return False

        elif self.selected_type == "folder":
            if not source.is_dir():
                QMessageBox.warning(
                    self,
                    "Invalid source",
                    "The selected path is no longer a folder.",
                )
                return False

        else:
            QMessageBox.warning(
                self,
                "Invalid source",
                "Please choose a valid file or folder.",
            )
            return False

        # -----------------------------------------------------
        # Output
        # -----------------------------------------------------

        output = self._effective_output_path()

        if not output:
            QMessageBox.warning(
                self,
                "Output required",
                "Please choose an encrypted output location.",
            )
            return False

        output_path = Path(output)

        if output_path.resolve() == source.resolve():
            QMessageBox.warning(
                self,
                "Invalid output",
                "The encrypted output cannot be the same as the source.",
            )
            return False

        # -----------------------------------------------------
        # Password
        # -----------------------------------------------------

        password = (
            self.password.text()
            if self.password
            else ""
        )

        confirmation = (
            self.confirm_password.text()
            if self.confirm_password
            else ""
        )

        if not password:
            QMessageBox.warning(
                self,
                "Password required",
                "Please enter a password.",
            )

            if self.password:
                self.password.setFocus()

            return False

        if len(password) < 8:
            QMessageBox.warning(
                self,
                "Password too short",
                "Please use at least 8 characters.",
            )

            if self.password:
                self.password.setFocus()

            return False

        if password != confirmation:
            QMessageBox.warning(
                self,
                "Password mismatch",
                "The passwords do not match.",
            )

            if self.confirm_password:
                self.confirm_password.setFocus()

            return False

        # -----------------------------------------------------
        # Recovery
        # -----------------------------------------------------

        if not self.recovery_destination_path:
            QMessageBox.warning(
                self,
                "Recovery location required",
                "Choose a folder where the recovery key will be saved.",
            )
            return False

        recovery_dir = Path(
            self.recovery_destination_path
        )

        if not recovery_dir.exists():
            QMessageBox.warning(
                self,
                "Recovery location unavailable",
                "The selected recovery folder no longer exists.",
            )
            return False

        if not recovery_dir.is_dir():
            QMessageBox.warning(
                self,
                "Invalid recovery location",
                "The recovery destination must be a folder.",
            )
            return False

        # -----------------------------------------------------
        # Recovery filename
        # -----------------------------------------------------

        filename = (
            self.recovery_filename.text().strip()
            if self.recovery_filename
            else ""
        )

        if not filename:
            QMessageBox.warning(
                self,
                "Recovery filename required",
                "Please provide a recovery-key filename.",
            )

            if self.recovery_filename:
                self.recovery_filename.setFocus()

            return False

        if "/" in filename or "\\" in filename:
            QMessageBox.warning(
                self,
                "Invalid recovery filename",
                "The recovery filename must contain only a filename, "
                "not a folder path.",
            )
            return False

        return True

    # =========================================================
    # START ENCRYPTION
    # =========================================================

    def _start_encryption(self) -> None:
        if self._busy:
            return

        if not self._validate_form():
            return

        output = self._effective_output_path()

        overwrite = (
            self.overwrite_checkbox.isChecked()
        )

        output_exists = Path(
            output
        ).exists()

        if output_exists and not overwrite:
            answer = QMessageBox.question(
                self,
                "Output already exists",
                "An encrypted output with this name already exists.\n\n"
                "Do you want to replace it?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )

            if answer != QMessageBox.Yes:
                return

            overwrite = True

        # -----------------------------------------------------
        # Final confirmation
        # -----------------------------------------------------

        source_name = Path(
            self.selected_path
        ).name

        confirmation = QMessageBox.question(
            self,
            "Start encryption?",
            f"Encrypt:\n{source_name}\n\n"
            f"Algorithm: {self.algorithm}\n"
            f"Output:\n{output}\n\n"
            "A recovery key will also be saved separately.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes,
        )

        if confirmation != QMessageBox.Yes:
            return

        self._launch_worker(
            output,
            overwrite,
        )

    def _launch_worker(
        self,
        output: str,
        overwrite: bool,
    ) -> None:
        self._busy = True

        self._set_busy_state(True)

        if self.progress_bar:
            self.progress_bar.setRange(
                0,
                0,
            )

        if self.progress_label:
            self.progress_label.setText(
                "Working…"
            )

        if self.status_label:
            self.status_label.setText(
                "Encrypting securely. Please wait…"
            )

        recovery_filename = (
            self.recovery_filename.text().strip()
            if self.recovery_filename
            else None
        )

        password = (
            self.password.text()
            if self.password
            else ""
        )

        self._thread = QThread(self)

        self._worker = EncryptionWorker(
            source=self.selected_path,
            source_type=self.selected_type,
            destination=output,
            algorithm=self.algorithm,
            password=password,
            recovery_storage=(
                self.recovery_destination_type
            ),
            recovery_destination=(
                self.recovery_destination_path
            ),
            recovery_filename=recovery_filename,
            overwrite=overwrite,
        )

        self._worker.moveToThread(
            self._thread
        )

        self._thread.started.connect(
            self._worker.run
        )

        self._worker.finished.connect(
            self._encryption_finished
        )

        self._worker.failed.connect(
            self._encryption_failed
        )

        self._worker.finished.connect(
            self._thread.quit
        )

        self._worker.failed.connect(
            self._thread.quit
        )

        self._thread.finished.connect(
            self._worker.deleteLater
        )

        self._thread.finished.connect(
            self._thread_finished
        )

        self._thread.start()

    # =========================================================
    # WORKER FINISH
    # =========================================================

    def _encryption_finished(
        self,
        result,
    ) -> None:
        self._busy = False

        output = getattr(
            result,
            "output",
            self._effective_output_path(),
        )

        recovery_saved = bool(
            getattr(
                result,
                "recovery_saved",
                False,
            )
        )

        algorithm = getattr(
            result,
            "algorithm",
            self.algorithm,
        )

        if self.progress_bar:
            self.progress_bar.setRange(
                0,
                1,
            )

            self.progress_bar.setValue(
                1
            )

        if self.progress_label:
            self.progress_label.setText(
                "Complete"
            )

        if self.status_label:
            self.status_label.setText(
                "✓ Encryption completed successfully."
            )

        self._set_busy_state(False)

        recovery_text = (
            self.recovery_destination_path
            if recovery_saved
            else "Recovery key storage was not confirmed."
        )

        QMessageBox.information(
            self,
            "Encryption complete",
            "Your data has been encrypted successfully.\n\n"
            f"Algorithm:\n{algorithm}\n\n"
            f"Encrypted output:\n{output}\n\n"
            f"Recovery key folder:\n{recovery_text}\n\n"
            "Keep the recovery key in a safe place.",
        )

    def _encryption_failed(
        self,
        error,
    ) -> None:
        self._busy = False

        if self.progress_bar:
            self.progress_bar.setRange(
                0,
                1,
            )

            self.progress_bar.setValue(
                0
            )

        if self.progress_label:
            self.progress_label.setText(
                "Failed"
            )

        self._set_busy_state(False)

        message = str(
            error
        ).strip()

        if not message:
            message = (
                "Encryption could not be completed."
            )

        if self.status_label:
            self.status_label.setText(
                "✕ Encryption failed."
            )

        QMessageBox.critical(
            self,
            "Encryption failed",
            "CipherForge could not complete the encryption operation.\n\n"
            f"{message}",
        )

    def _thread_finished(self) -> None:
        self._worker = None

        if self._thread is not None:
            self._thread.deleteLater()

        self._thread = None

    # =========================================================
    # BUSY STATE
    # =========================================================

    def _set_busy_state(
        self,
        busy: bool,
    ) -> None:
        widgets = (
            self.encrypt_button,
            self.reset_button,
            self.choose_output_button,
            self.aes_radio,
            self.chacha_radio,
            self.local_recovery,
            self.usb_recovery,
            self.password,
            self.confirm_password,
            self.recovery_filename,
            self.overwrite_checkbox,
        )

        for widget in widgets:
            if widget is not None:
                widget.setEnabled(
                    not busy
                )

        # Source-selection buttons are found by object name.
        for button in self.findChildren(
            QPushButton
        ):
            if button in (
                self.encrypt_button,
                self.reset_button,
                self.choose_output_button,
            ):
                continue

            text = button.text().lower()

            if (
                "choose file" in text
                or "choose folder" in text
            ):
                button.setEnabled(
                    not busy
                )

    # =========================================================
    # RESET
    # =========================================================

    def reset_form(self) -> None:
        if self._busy:
            return

        self.selected_path = ""
        self.selected_type = ""
        self.output_path = ""

        self.algorithm = "AES-256-GCM"

        self.recovery_destination_type = "local"
        self.recovery_destination_path = ""

        if self.aes_radio:
            self.aes_radio.setChecked(True)

        if self.password:
            self.password.clear()

        if self.confirm_password:
            self.confirm_password.clear()

        if self.recovery_filename:
            self.recovery_filename.setText(
                "CipherForge_Recovery_Key.cfrecovery"
            )

        if self.overwrite_checkbox:
            self.overwrite_checkbox.setChecked(
                False
            )

        if self.local_recovery:
            self.local_recovery.blockSignals(True)
            self.local_recovery.setChecked(True)
            self.local_recovery.blockSignals(False)

        if self.usb_recovery:
            self.usb_recovery.blockSignals(True)
            self.usb_recovery.setChecked(False)
            self.usb_recovery.blockSignals(False)

        self._update_algorithm_cards()
        self._update_recovery_cards()

        if self.selected_label:
            self.selected_label.setText(
                "No file or folder selected."
            )

        if self.output_label:
            self.output_label.setText(
                "Default output location will be used."
            )

        if self.recovery_location:
            self.recovery_location.setText(
                "📁  Choose a recovery-key folder "
                "before encryption."
            )

        if self.password_strength:
            self.password_strength.setText(
                "Password strength: —"
            )

        if self.password_match:
            self.password_match.setText(
                ""
            )

        if self.status_label:
            self.status_label.setText(
                "Ready — select a file or folder to begin."
            )

        if self.progress_label:
            self.progress_label.setText(
                ""
            )

        if self.progress_bar:
            self.progress_bar.setRange(
                0,
                1,
            )

            self.progress_bar.setValue(
                0
            )

    # =========================================================
    # LIFECYCLE SAFETY
    # =========================================================

    def closeEvent(self, event) -> None:
        """
        Prevent closing the page while the worker is active.
        """

        if self._busy:
            QMessageBox.information(
                self,
                "Encryption in progress",
                "Please wait until the current encryption operation finishes.",
            )

            event.ignore()
            return

        event.accept()
