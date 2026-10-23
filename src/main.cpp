#include <QApplication>
#include "MainWindow.h"
int main(int argc,char **argv) {
    QApplication app(argc,argv);
    app.setApplicationName("YAS BinaryLab X");
    MainWindow window;
    window.show();
    return app.exec();
}
