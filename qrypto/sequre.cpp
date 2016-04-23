#include "sequre.h"

#include <QString>

namespace Qrypto
{
template class Sequre<QByteArray>;
template class Sequre<QString, int, QChar>;
template class Sequre<std::string, size_t>;
template class Sequre<std::vector<uchar>, size_t, uchar>;
}
