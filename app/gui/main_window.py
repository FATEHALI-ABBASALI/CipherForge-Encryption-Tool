from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from .encryption_page import EncryptionPage
from .decryption_page import DecryptionPage
from .settings_page import SettingsPage


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle(
            "CipherForge — Secure File & Folder Encryption"
        )
        self.resize(1400, 900)
        self.setMinimumSize(1050, 700)

        self.current_theme = "dark"

        self._build_ui()
        self.apply_theme("dark")
        self._connect_signals()

    # ---------------------------------------------------------
    # UI
    # ---------------------------------------------------------

    def _build_ui(self):
        central = QWidget()
        central.setObjectName("appRoot")
        self.setCentralWidget(central)

        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Sidebar
        self.sidebar = self._create_sidebar()
        root_layout.addWidget(self.sidebar)

        # Main area
        main_container = QWidget()
        main_layout = QVBoxLayout(main_container)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self.topbar = self._create_topbar()
        main_layout.addWidget(self.topbar)

        self.pages = QStackedWidget()
        self.pages.setSizePolicy(
            QSizePolicy.Expanding,
            QSizePolicy.Expanding,
        )

        self.encryption_page = EncryptionPage()
        self.decryption_page = DecryptionPage()
        self.settings_page = SettingsPage()

        self.pages.addWidget(self.encryption_page)
        self.pages.addWidget(self.decryption_page)
        self.pages.addWidget(self.settings_page)

        main_layout.addWidget(self.pages, 1)

        root_layout.addWidget(main_container, 1)

        self._select_page(0)

    def _create_sidebar(self):
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(270)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(20, 24, 20, 20)
        layout.setSpacing(8)

        # Brand
        brand_container = QWidget()
        brand_layout = QVBoxLayout(brand_container)
        brand_layout.setContentsMargins(8, 0, 8, 0)
        brand_layout.setSpacing(3)

        brand = QLabel("CIPHERFORGE")
        brand.setObjectName("brand")

        brand_subtitle = QLabel(
            "SECURE FILE PROTECTION"
        )
        brand_subtitle.setObjectName("brandSubtitle")

        brand_layout.addWidget(brand)
        brand_layout.addWidget(brand_subtitle)

        layout.addWidget(brand_container)
        layout.addSpacing(30)

        # Navigation label
        nav_label = QLabel("WORKSPACE")
        nav_label.setObjectName("navLabel")
        layout.addWidget(nav_label)
        layout.addSpacing(6)

        self.nav_encryption = self._nav_button(
            "🔒",
            "Encryption",
            "Protect files & folders",
        )

        self.nav_decryption = self._nav_button(
            "🔓",
            "Decryption",
            "Restore protected data",
        )

        self.nav_settings = self._nav_button(
            "⚙",
            "Settings",
            "Preferences & security",
        )

        layout.addWidget(self.nav_encryption)
        layout.addWidget(self.nav_decryption)
        layout.addWidget(self.nav_settings)

        layout.addStretch()

        # Security badge
        security_card = QFrame()
        security_card.setObjectName("securityCard")

        security_layout = QVBoxLayout(security_card)
        security_layout.setContentsMargins(
            14, 14, 14, 14
        )
        security_layout.setSpacing(5)

        security_title = QLabel(
            "●  SECURITY MODE"
        )
        security_title.setObjectName(
            "securityTitle"
        )

        security_text = QLabel(
            "Local processing\n"
            "No cloud upload"
        )
        security_text.setObjectName(
            "securityText"
        )

        security_layout.addWidget(
            security_title
        )
        security_layout.addWidget(
            security_text
        )

        layout.addWidget(security_card)
        layout.addSpacing(12)

        version = QLabel(
            "CipherForge v0.1  •  GUI Preview"
        )
        version.setObjectName("version")

        layout.addWidget(version)

        return sidebar

    def _nav_button(
        self,
        icon: str,
        title: str,
        subtitle: str,
    ):
        button = QPushButton()
        button.setObjectName("navButton")
        button.setCursor(Qt.PointingHandCursor)
        button.setMinimumHeight(66)
        button.setMaximumHeight(66)

        layout = QHBoxLayout(button)
        layout.setContentsMargins(
            13, 8, 12, 8
        )
        layout.setSpacing(12)

        icon_label = QLabel(icon)
        icon_label.setObjectName("navIcon")
        icon_label.setFixedWidth(28)
        icon_label.setAlignment(
            Qt.AlignCenter
        )

        text_container = QWidget()
        text_layout = QVBoxLayout(
            text_container
        )
        text_layout.setContentsMargins(
            0, 0, 0, 0
        )
        text_layout.setSpacing(1)

        title_label = QLabel(title)
        title_label.setObjectName(
            "navTitle"
        )

        subtitle_label = QLabel(subtitle)
        subtitle_label.setObjectName(
            "navSubtitle"
        )

        text_layout.addWidget(title_label)
        text_layout.addWidget(
            subtitle_label
        )

        layout.addWidget(icon_label)
        layout.addWidget(
            text_container,
            1,
        )

        return button

    def _create_topbar(self):
        topbar = QFrame()
        topbar.setObjectName("topbar")
        topbar.setFixedHeight(72)

        layout = QHBoxLayout(topbar)
        layout.setContentsMargins(
            30, 0, 30, 0
        )

        page_context = QLabel(
            "Secure File & Folder Encryption"
        )
        page_context.setObjectName(
            "topbarContext"
        )

        layout.addWidget(page_context)

        layout.addStretch()

        protection = QLabel(
            "●  LOCAL PROTECTION"
        )
        protection.setObjectName(
            "protectionBadge"
        )

        layout.addWidget(protection)

        return topbar

    # ---------------------------------------------------------
    # Navigation
    # ---------------------------------------------------------

    def _connect_signals(self):
        self.nav_encryption.clicked.connect(
            lambda: self._select_page(0)
        )

        self.nav_decryption.clicked.connect(
            lambda: self._select_page(1)
        )

        self.nav_settings.clicked.connect(
            lambda: self._select_page(2)
        )

        self.settings_page.theme_changed.connect(
            self.apply_theme
        )

    def _select_page(self, index: int):
        self.pages.setCurrentIndex(index)

        buttons = [
            self.nav_encryption,
            self.nav_decryption,
            self.nav_settings,
        ]

        for i, button in enumerate(buttons):
            button.setProperty(
                "active",
                i == index,
            )
            self._refresh_style(button)

    def _refresh_style(self, widget):
        widget.style().unpolish(widget)
        widget.style().polish(widget)
        widget.update()

    # ---------------------------------------------------------
    # Theme
    # ---------------------------------------------------------

    def apply_theme(self, theme: str):
        if theme == "system":
            theme = "dark"

        self.current_theme = theme

        if theme == "light":
            self._apply_light_theme()
        else:
            self._apply_dark_theme()

    def _apply_dark_theme(self):
        QApplication.instance().setStyleSheet(
            self._stylesheet(
                background="#070b14",
                sidebar="#0d1422",
                panel="#0f1726",
                panel2="#121c2d",
                border="#243248",
                text="#f8fafc",
                muted="#91a0b8",
                accent="#6d7cff",
                accent_hover="#7d8aff",
                input_bg="#0a111e",
                success="#36d399",
            )
        )

    def _apply_light_theme(self):
        QApplication.instance().setStyleSheet(
            self._stylesheet(
                background="#f4f7fb",
                sidebar="#ffffff",
                panel="#ffffff",
                panel2="#f8fafc",
                border="#dbe2ec",
                text="#172033",
                muted="#667085",
                accent="#5365e8",
                accent_hover="#4557dc",
                input_bg="#f8fafc",
                success="#079455",
            )
        )

    def _stylesheet(
        self,
        background,
        sidebar,
        panel,
        panel2,
        border,
        text,
        muted,
        accent,
        accent_hover,
        input_bg,
        success,
    ):
        return f"""
        * {{
            font-family: "Segoe UI";
            font-size: 13px;
        }}

        QMainWindow,
        QWidget#appRoot {{
            background: {background};
            color: {text};
        }}

        QFrame#sidebar {{
            background: {sidebar};
            border-right: 1px solid {border};
        }}

        QLabel#brand {{
            color: {text};
            font-size: 25px;
            font-weight: 800;
            letter-spacing: 1px;
        }}

        QLabel#brandSubtitle {{
            color: {muted};
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 1.5px;
        }}

        QLabel#navLabel {{
            color: {muted};
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 1.4px;
            padding-left: 8px;
        }}

        QPushButton#navButton {{
            background: transparent;
            border: 1px solid transparent;
            border-radius: 11px;
            color: {text};
            text-align: left;
        }}

        QPushButton#navButton:hover {{
            background: {panel2};
            border-color: {border};
        }}

        QPushButton#navButton[active="true"] {{
            background: {panel2};
            border-color: {accent};
        }}

        QLabel#navIcon {{
            font-size: 19px;
        }}

        QLabel#navTitle {{
            color: {text};
            font-size: 14px;
            font-weight: 700;
        }}

        QLabel#navSubtitle {{
            color: {muted};
            font-size: 10px;
        }}

        QFrame#securityCard {{
            background: {panel2};
            border: 1px solid {border};
            border-radius: 11px;
        }}

        QLabel#securityTitle {{
            color: {success};
            font-size: 10px;
            font-weight: 800;
        }}

        QLabel#securityText {{
            color: {muted};
            font-size: 10px;
            line-height: 1.4;
        }}

        QLabel#version {{
            color: {muted};
            font-size: 10px;
            padding-left: 2px;
        }}

        QFrame#topbar {{
            background: {panel};
            border-bottom: 1px solid {border};
        }}

        QLabel#topbarContext {{
            color: {muted};
            font-size: 12px;
        }}

        QLabel#protectionBadge {{
            background: {panel2};
            border: 1px solid {border};
            border-radius: 14px;
            padding: 7px 12px;
            color: {success};
            font-size: 10px;
            font-weight: 700;
        }}

        QScrollArea {{
            background: transparent;
            border: none;
        }}

        QScrollBar:vertical {{
            background: transparent;
            width: 9px;
            margin: 4px 2px 4px 0;
        }}

        QScrollBar::handle:vertical {{
            background: {border};
            border-radius: 4px;
            min-height: 40px;
        }}

        QScrollBar::add-line:vertical,
        QScrollBar::sub-line:vertical {{
            height: 0px;
        }}

        QFrame[card="true"] {{
            background: {panel};
            border: 1px solid {border};
            border-radius: 14px;
        }}

        QLabel#pageTitle {{
            color: {text};
            font-size: 30px;
            font-weight: 800;
        }}

        QLabel#pageSubtitle {{
            color: {muted};
            font-size: 13px;
        }}

        QLabel#sectionNumber {{
            background: {accent};
            color: white;
            border-radius: 10px;
            min-width: 24px;
            max-width: 24px;
            min-height: 24px;
            max-height: 24px;
            font-size: 11px;
            font-weight: 800;
            qproperty-alignment: AlignCenter;
        }}

        QLabel#sectionTitle {{
            color: {text};
            font-size: 15px;
            font-weight: 750;
        }}

        QLabel#sectionHint {{
            color: {muted};
            font-size: 11px;
        }}

        QLabel#fieldLabel {{
            color: {text};
            font-size: 12px;
            font-weight: 650;
        }}

        QLineEdit,
        QComboBox {{
            background: {input_bg};
            border: 1px solid {border};
            border-radius: 9px;
            color: {text};
            padding: 11px 12px;
            min-height: 19px;
        }}

        QLineEdit:focus,
        QComboBox:focus {{
            border: 1px solid {accent};
        }}

        QComboBox::drop-down {{
            border: none;
            width: 30px;
        }}

        QComboBox QAbstractItemView {{
            background: {panel};
            color: {text};
            border: 1px solid {border};
            selection-background-color: {accent};
        }}

        QPushButton#secondaryButton {{
            background: {panel2};
            border: 1px solid {border};
            border-radius: 9px;
            color: {text};
            padding: 10px 16px;
            font-weight: 650;
        }}

        QPushButton#secondaryButton:hover {{
            border-color: {accent};
        }}

        QPushButton#primaryButton {{
            background: {accent};
            border: 1px solid {accent};
            border-radius: 10px;
            color: white;
            padding: 13px 18px;
            font-size: 14px;
            font-weight: 750;
        }}

        QPushButton#primaryButton:hover {{
            background: {accent_hover};
        }}

        QPushButton#primaryButton:disabled {{
            background: {border};
            border-color: {border};
            color: {muted};
        }}

        QFrame#dropZone {{
            background: {input_bg};
            border: 1px dashed {accent};
            border-radius: 12px;
        }}

        QLabel#dropIcon {{
            font-size: 30px;
        }}

        QLabel#dropTitle {{
            color: {text};
            font-size: 14px;
            font-weight: 750;
        }}

        QLabel#dropHint {{
            color: {muted};
            font-size: 11px;
        }}

        QFrame#algorithmCard {{
            background: {input_bg};
            border: 1px solid {border};
            border-radius: 10px;
        }}

        QFrame#algorithmCard[selected="true"] {{
            border: 1px solid {accent};
            background: {panel2};
        }}

        QLabel#algorithmName {{
            color: {text};
            font-size: 13px;
            font-weight: 750;
        }}

        QLabel#algorithmDescription {{
            color: {muted};
            font-size: 10px;
        }}

        QLabel#algorithmBadge {{
            color: {accent};
            font-size: 9px;
            font-weight: 800;
        }}

        QRadioButton {{
            color: {text};
            spacing: 8px;
            font-size: 12px;
        }}

        QRadioButton::indicator {{
            width: 17px;
            height: 17px;
        }}

        QProgressBar {{
            background: {input_bg};
            border: none;
            border-radius: 4px;
            height: 7px;
            text-align: center;
        }}

        QProgressBar::chunk {{
            background: {accent};
            border-radius: 4px;
        }}

        QLabel#statusText {{
            color: {muted};
            font-size: 10px;
        }}

        QLabel#successText {{
            color: {success};
            font-weight: 700;
        }}

        QLabel#recoveryKey {{
            background: {input_bg};
            border: 1px solid {border};
            border-radius: 9px;
            padding: 13px;
            color: {text};
            font-family: "Consolas";
            font-size: 12px;
        }}

        QCheckBox {{
            color: {text};
            spacing: 8px;
        }}
        """