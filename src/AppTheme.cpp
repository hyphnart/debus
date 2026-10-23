#include "AppTheme.h"
#include <QApplication>
#include <QPalette>
#include <QColor>
#include <QStyleFactory>
void AppTheme::apply(QApplication *app,bool dark) {
    app->setStyle(QStyleFactory::create("Fusion"));
    const QColor bg=dark?QColor("#05070d"):QColor("#f3f6fb");
    const QColor panel=dark?QColor("#0a101c"):QColor("#ffffff");
    const QColor field=dark?QColor("#0d1626"):QColor("#ffffff");
    const QColor text=dark?QColor("#dce7f6"):QColor("#162338");
    const QColor inactive=dark?QColor("#70819b"):QColor("#7b8798");
    const QColor accent=dark?QColor("#3b82f6"):QColor("#2563eb");
    QPalette palette;
    palette.setColor(QPalette::Window,bg);
    palette.setColor(QPalette::WindowText,text);
    palette.setColor(QPalette::Base,field);
    palette.setColor(QPalette::AlternateBase,panel);
    palette.setColor(QPalette::Text,text);
    palette.setColor(QPalette::Button,panel);
    palette.setColor(QPalette::ButtonText,text);
    palette.setColor(QPalette::ToolTipBase,panel);
    palette.setColor(QPalette::ToolTipText,text);
    palette.setColor(QPalette::Highlight,accent);
    palette.setColor(QPalette::HighlightedText,QColor("#ffffff"));
    palette.setColor(QPalette::PlaceholderText,inactive);
    palette.setColor(QPalette::Disabled,QPalette::Text,inactive);
    palette.setColor(QPalette::Disabled,QPalette::ButtonText,inactive);
    app->setPalette(palette);
    const QString border=dark?"#17243a":"#d9e0eb";
    const QString hover=dark?"#152842":"#e7f0ff";
    const QString selected=dark?"#1d3d69":"#d4e5ff";
    app->setStyleSheet(QString(R"QSS(
       QMainWindow,QDialog,QWidget { background:%1; color:%4; }
       QMenuBar,QMenu,QToolBar,QStatusBar {background:%2;color:%4;border:0;}
       QMenuBar::item:selected,QMenu::item:selected {background:%7;}
       QDockWidget {font-weight:600;titlebar-close-icon:none;}
       QDockWidget::title {background:%2;padding:8px;border-bottom:1px solid %5;}
       QTabWidget::pane {border:1px solid %5;background:%2;}
       QTabBar::tab {background:%2;color:%4;border:1px solid %5;padding:9px 17px;}
       QTabBar::tab:selected {background:%7;border-bottom:2px solid %6;}
       QTabBar::tab:hover {background:%8;}
       QTreeWidget,QTableWidget,QListWidget,QPlainTextEdit,QTextEdit,QLineEdit,QSpinBox,QComboBox {
           background:%3;color:%4;alternate-background-color:%2;
           border:1px solid %5;selection-background-color:%7;selection-color:%4;
       }
       QHeaderView::section {background:%2;color:%4;padding:6px;border:0;border-bottom:1px solid %5;}
       QPushButton {background:%2;border:1px solid %5;border-radius:5px;padding:6px 12px;}
       QPushButton:hover {background:%8;border-color:%6;}
       QProgressBar {background:%2;color:%4;border:1px solid %5;}
       QProgressBar::chunk {background:%6;}
       QScrollBar:vertical,QScrollBar:horizontal {background:%1;}
       QScrollBar::handle:vertical,QScrollBar::handle:horizontal {background:%5;min-width:10px;min-height:14px;}
       QToolTip {background:%2;color:%4;border:1px solid %5;}
    )QSS").arg(bg.name(),panel.name(),field.name(),text.name(),border,accent.name(),selected,hover));
}
