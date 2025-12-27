#include <QApplication>
#include <QMetaType>
#include "../core/PacketInfo.h"
#include "MainWindow.h"

int main(int argc, char *argv[]) {

    // Create Qt application object
    QApplication app(argc, argv);

    // Register PacketInfo type for Qt signals/slots across threads
    qRegisterMetaType<PacketInfo>("PacketInfo");

    // Create and show main window
    MainWindow w;
    w.show();

    // Start Qt event loop
    return app.exec();
}
