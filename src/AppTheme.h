#pragma once
#include <QString>
class QApplication;
class AppTheme {
public:
    static void apply(QApplication *app,bool dark);
};
