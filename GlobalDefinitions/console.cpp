#include "console.h"

namespace console
{
    QTextStream& qStdOut()
    {
        static QTextStream out(stdout);
        return out;
    }

    QTextStream& qStdIn()
    {
        static QTextStream in(stdin);
        return in;
    }

    QTextStream& qStdErr()
    {
        static QTextStream err(stderr);
        return err;
    }
}
