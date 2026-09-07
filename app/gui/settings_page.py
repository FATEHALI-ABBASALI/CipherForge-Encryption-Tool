from PySide6.QtCore import Signal, Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core import app_service


class SettingsPage(QWidget):
    theme_changed = Signal(str)

    def __init__(self):
        super().__init__()

        self._build_ui()
        self._load_preferences()

    def _load_preferences(self):
        try:
            config = app_service.get_service_config()
        except Exception:
            return

        algorithm = config.get("algorithm")
        if algorithm == "chacha20-poly1305":
            self.algorithm.setCurrentText("ChaCha20-Poly1305")
        else:
            self.algorithm.setCurrentText("AES-256-GCM")

        theme = config.get("theme")
        if theme in {"dark", "light"}:
            self.theme.setCurrentText(theme.title())

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
        title = QLabel("Settings")
        title.setObjectName(
            "pageTitle"
        )

        subtitle = QLabel(
            "Configure CipherForge appearance, algorithms "
            "and platform preferences."
        )
        subtitle.setObjectName(
            "pageSubtitle"
        )

        layout.addWidget(title)
        layout.addWidget(subtitle)

        # Security settings
        layout.addWidget(
            self._security_settings()
        )

        # Appearance
        layout.addWidget(
            self._appearance_settings()
        )

        # Platform
        layout.addWidget(
            self._platform_settings()
        )

        # About
        layout.addWidget(
            self._about_card()
        )

        layout.addStretch()

        scroll.setWidget(content)

        root = QVBoxLayout(self)
        root.setContentsMargins(
            0, 0, 0, 0
        )
        root.addWidget(scroll)

    # ---------------------------------------------------------
    # Card Header
    # ---------------------------------------------------------

    def _header(
        self,
        icon,
        title,
        subtitle,
    ):
        widget = QWidget()

        layout = QHBoxLayout(widget)
        layout.setContentsMargins(
            0, 0, 0, 8
        )
        layout.setSpacing(12)

        icon_label = QLabel(icon)
        icon_label.setObjectName(
            "sectionNumber"
        )
        icon_label.setAlignment(
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

        subtitle_label = QLabel(
            subtitle
        )
        subtitle_label.setObjectName(
            "sectionHint"
        )

        texts.addWidget(
            title_label
        )
        texts.addWidget(
            subtitle_label
        )

        layout.addWidget(
            icon_label
        )
        layout.addLayout(
            texts
        )
        layout.addStretch()

        return widget

    # ---------------------------------------------------------
    # Security
    # ---------------------------------------------------------

    def _security_settings(self):
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
                "🔐",
                "Encryption preferences",
                "Choose the default protection method.",
            )
        )

        grid = QGridLayout()
        grid.setHorizontalSpacing(15)
        grid.setVerticalSpacing(8)

        label = QLabel(
            "Default algorithm"
        )
        label.setObjectName(
            "fieldLabel"
        )

        self.algorithm = QComboBox()
        self.algorithm.addItems(
            [
                "AES-256-GCM",
                "ChaCha20-Poly1305",
            ]
        )

        label2 = QLabel(
            "Key derivation"
        )
        label2.setObjectName(
            "fieldLabel"
        )

        kdf = QComboBox()
        kdf.addItem(
            "Argon2id — recommended"
        )

        grid.addWidget(
            label,
            0,
            0,
        )

        grid.addWidget(
            label2,
            0,
            1,
        )

        grid.addWidget(
            self.algorithm,
            1,
            0,
        )

        grid.addWidget(
            kdf,
            1,
            1,
        )

        layout.addLayout(grid)

        info = QLabel(
            "Argon2id will be used later to derive strong "
            "encryption keys from user passwords."
        )
        info.setObjectName(
            "sectionHint"
        )
        info.setWordWrap(True)

        layout.addWidget(
            info
        )

        return card

    # ---------------------------------------------------------
    # Appearance
    # ---------------------------------------------------------

    def _appearance_settings(self):
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
                "🎨",
                "Appearance",
                "Customize how CipherForge looks.",
            )
        )

        row = QHBoxLayout()
        row.setSpacing(15)

        label = QLabel(
            "Application theme"
        )
        label.setObjectName(
            "fieldLabel"
        )

        self.theme = QComboBox()
        self.theme.addItems(
            [
                "Dark",
                "Light",
                "System",
            ]
        )

        self.theme.currentTextChanged.connect(
            self._theme_changed
        )

        row.addWidget(
            label
        )
        row.addStretch()
        row.addWidget(
            self.theme
        )

        layout.addLayout(row)

        return card

    def _theme_changed(self, value):
        self.theme_changed.emit(
            value.lower()
        )

    # ---------------------------------------------------------
    # Platform
    # ---------------------------------------------------------

    def _platform_settings(self):
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
                "💻",
                "Platform support",
                "CipherForge is designed for desktop systems.",
            )
        )

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)

        platforms = [
            (
                "Windows",
                "Primary development platform",
            ),
            (
                "Ubuntu Linux",
                "Supported desktop environment",
            ),
            (
                "Kali Linux",
                "Supported security environment",
            ),
        ]

        for index, (name, description) in enumerate(
            platforms
        ):
            item = QFrame()
            item.setObjectName(
                "algorithmCard"
            )

            item_layout = QVBoxLayout(item)
            item_layout.setContentsMargins(
                14, 12, 14, 12
            )

            title = QLabel(
                name
            )
            title.setObjectName(
                "algorithmName"
            )

            desc = QLabel(
                description
            )
            desc.setObjectName(
                "algorithmDescription"
            )

            item_layout.addWidget(
                title
            )
            item_layout.addWidget(
                desc
            )

            grid.addWidget(
                item,
                index // 2,
                index % 2,
            )

        layout.addLayout(
            grid
        )

        return card

    # ---------------------------------------------------------
    # About
    # ---------------------------------------------------------

    def _about_card(self):
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
                "🛡",
                "About CipherForge",
                "Secure File & Folder Encryption",
            )
        )

        description = QLabel(
            "CipherForge is a local-first encryption application "
            "designed to protect files and folders without requiring "
            "cloud storage."
        )
        description.setObjectName(
            "sectionHint"
        )
        description.setWordWrap(True)

        layout.addWidget(
            description
        )

        save = QPushButton(
            "Save Preferences"
        )
        save.setObjectName(
            "primaryButton"
        )
        save.setMinimumHeight(44)
        save.setCursor(
            Qt.PointingHandCursor
        )

        save.clicked.connect(
            self._save_settings
        )

        layout.addWidget(
            save
        )

        return card

    def _save_settings(self):
        algorithm = (
            "aes-256-gcm"
            if self.algorithm.currentText() == "AES-256-GCM"
            else "chacha20-poly1305"
        )
        try:
            app_service.save_preferences(
                algorithm=algorithm,
                theme=self.theme.currentText().lower(),
            )
        except Exception as exc:
            QMessageBox.critical(
                self, "Settings not saved", str(app_service.safe_error(exc)),
            )
            return

        QMessageBox.information(
            self, "Settings Saved",
            "Your CipherForge preferences have been saved.",
        )
