#include "../qryptocompress.h"

#include <QScopedPointer>

#include <cryptopp/gzip.h>
#include <cryptopp/zlib.h>

using namespace Qrypto;

const QStringList Compress::AlgorithmNames =
        QStringList() << "Identity" << "Deflate" << "GZip" << "ZLib" << QString();

Error Compress::deflate(QByteArray &compressed, const QByteArray &data, int deflateLevel)
{
    std::string dst;
    QScopedPointer<CryptoPP::Deflator> deflator;
    deflateLevel = qBound(0, deflateLevel, 9);

    switch (algorithm) {
    case Identity:
        compressed = data;
        return NoError;
    case Deflate:
        deflator.reset(new CryptoPP::Deflator(new CryptoPP::StringSink(dst), deflateLevel));
        break;
    case GZip:
        deflator.reset(new CryptoPP::Gzip(new CryptoPP::StringSink(dst), deflateLevel));
        break;
    case ZLib:
        deflator.reset(new CryptoPP::ZlibCompressor(new CryptoPP::StringSink(dst), deflateLevel));
        break;
    default:
        return NotImplemented;
    }

    try {
        compressed.clear();
        CryptoPP::StringSource(data.toStdString(), true, deflator.take());
        QByteArray::fromStdString(dst).swap(compressed);
        return NoError;
    } catch (const std::bad_alloc &exc) {
        return OutOfMemory;
    } catch (const std::exception &exc) {
        qCritical(exc.what());
        return UnknownError;
    }
}

Error Compress::inflate(QByteArray &data, const QByteArray &compressed, bool repeat)
{
    std::string dst;
    QScopedPointer<CryptoPP::Inflator> inflator;

    switch (algorithm) {
    case Identity:
        data = compressed;
        return NoError;
    case Deflate:
        inflator.reset(new CryptoPP::Inflator(new CryptoPP::StringSink(dst), repeat));
        break;
    case GZip:
        inflator.reset(new CryptoPP::Gunzip(new CryptoPP::StringSink(dst), repeat));
        break;
    case ZLib:
        inflator.reset(new CryptoPP::ZlibDecompressor(new CryptoPP::StringSink(dst), repeat));
        break;
    default:
        return NotImplemented;
    }

    try {
        data.clear();
        CryptoPP::StringSource(compressed.toStdString(), true, inflator.take());
        QByteArray::fromStdString(dst).swap(data);
        return NoError;
    } catch (const std::bad_alloc &exc) {
        return OutOfMemory;
    } catch (const CryptoPP::Exception &exc) {
        switch (exc.GetErrorType()) {
        case CryptoPP::Exception::INVALID_DATA_FORMAT:
            return InvalidFormat;
        case CryptoPP::Exception::DATA_INTEGRITY_CHECK_FAILED:
            return IntegrityError;
        default:
            qCritical(exc.what());
            return UnknownError;
        }
    } catch (const std::exception &exc) {
        qCritical(exc.what());
        return UnknownError;
    }
}
