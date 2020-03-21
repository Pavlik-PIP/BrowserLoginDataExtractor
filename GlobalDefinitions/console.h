#ifndef CONSOLE_H
#define CONSOLE_H

#include <QTextStream>

namespace console
{
    QTextStream& qStdOut();
    QTextStream& qStdIn();
    QTextStream& qStdErr();
}

#endif // CONSOLE_H
