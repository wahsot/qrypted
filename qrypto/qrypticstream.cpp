#include "qrypticstream.h"

#include <QXmlStreamReader>
#include <QXmlStreamWriter>

#include "pointerator.h"
#include "qryptocipher.h"
#include "qryptocompress.h"
#include "qryptokeymaker.h"
#include "sequre.h"

struct QryptIO::Private
{
    static const QStringList CrypticV1;
    static const QStringList CrypticV2;
    Qrypto::Error error;
    QryptIO::Status status;
    QIODevice *device;
    int crypticVersion;
    QByteArray crypt;
    Qrypto::SequreBytes plain;
    Qrypto::Compress compress;
    Qrypto::Cipher cipher;
    Qrypto::KeyMaker keyMaker;

    Private(QIODevice *device) :
        error(Qrypto::NoError),
        status(QryptIO::Ok),
        device(device),
        crypticVersion(-1)
    { }

    bool isReadable()
    {
        return device && (device->isReadable() || device->open(QIODevice::ReadOnly)) && !device->atEnd();
    }

    bool isWritable()
    {
        return device && (device->isWritable() || device->open(QIODevice::WriteOnly));
    }

    bool loadV1()
    {
        Q_ASSERT(crypticVersion > 0);
        QXmlStreamReader xml(device);
        int from = 0;
        crypt.clear();

        if (!xml.readNextStartElement())
            return false;

        for (QString path; !xml.atEnd(); ) {
            switch (xml.readNext()) {
            case QXmlStreamReader::StartElement:
                path += '/';
                path += xml.name();

                switch (CrypticV1.indexOf(path, from)) {
                case 0: keyMaker.setAlgorithmName(xml.readElementText()); break;
                case 1: keyMaker.setSalt(xml.readElementText()); break;
                case 2: keyMaker.setIterationCount(xml.readElementText().toUInt()); break;
                case 3: keyMaker.setKeyLength(xml.readElementText().toUInt()); break;
                case 4: cipher.setAlgorithmName(xml.readElementText()); break;
                case 5: cipher.setOperationCode(xml.readElementText()); break;
                case 6: cipher.setInitialVector(xml.readElementText()); break;
                case 7:
                    crypt += QByteArray::fromBase64(xml.readElementText().toLatin1());
                    --from; // may occur many times
                    break;
                case 8:
                    crypt += QByteArray::fromHex(xml.readElementText().toLatin1());
                    --from; // may occur many times
                    break;
                case 9: plain.reserve(xml.readElementText().toUInt()); break;
                default:
                    continue;
                }

                ++from;
                /* FALLTHRU */
            case QXmlStreamReader::EndElement:
                path = path.section('/', 0, -2);
                break;
            default:
                continue;
            }
        }

        return !xml.hasError();
    }

    bool loadV2()
    {
        Q_ASSERT(crypticVersion > 0);
        QXmlStreamReader xml(device);
        int from = 0;
        crypt.clear();

        if (!xml.readNextStartElement())
            return false;

        for (QString path; !xml.atEnd(); ) {
            switch (xml.readNext()) {
            case QXmlStreamReader::StartElement:
                path += '/';
                path += xml.name();

                switch (CrypticV2.indexOf(path, from)) {
                case  0: keyMaker.setAlgorithmName(xml.readElementText()); break;
                case  1: keyMaker.setSalt(xml.readElementText()); break;
                case  2: keyMaker.setIterationCount(xml.readElementText().toUInt()); break;
                case  3: keyMaker.setKeyLength(xml.readElementText().toUInt()); break;
                case  4: cipher.setAlgorithmName(xml.readElementText()); break;
                case  5: cipher.setOperationCode(xml.readElementText()); break;
                case  6: cipher.setInitialVector(xml.readElementText()); break;
                case  7:
                    crypt += QByteArray::fromBase64(xml.readElementText().toLatin1());
                    --from; // may occur many times
                    break;
                case  8:
                    crypt += QByteArray::fromHex(xml.readElementText().toLatin1());
                    --from; // may occur many times
                    break;
                case  9: plain.reserve(xml.readElementText().toUInt()); break;
                case 10: cipher.setAuthentication(xml.readElementText()); break;
                case 11: compress.setAlgorithmName(xml.readElementText()); break;
                default:
                    continue;
                }

                ++from;
                /* FALLTHRU */
            case QXmlStreamReader::EndElement:
                path = path.section('/', 0, -2);
                break;
            default:
                continue;
            }
        }

        return !xml.hasError();
    }

    bool save()
    {
        QXmlStreamWriter xml(device);

        xml.setAutoFormatting(true);
        xml.setAutoFormattingIndent(-1);

        xml.writeStartDocument();
        xml.writeDefaultNamespace("file://cryptic-V2.xsd");
        xml.writeNamespace("http://www.w3.org/2001/XMLSchema-instance", "xsi");
        xml.writeStartElement("file://cryptic-V2.xsd", "Cryptic");
        xml.writeAttribute("schemaVersion", QString::number(crypticVersion));

        xml.writeStartElement("Header");
        xml.writeTextElement("Digest", keyMaker.algorithmName());
        xml.writeTextElement("Salt", QString::fromLatin1(keyMaker.salt().toHex()));
        xml.writeTextElement("IterationCount", QString::number(keyMaker.iterationCount()));
        xml.writeTextElement("KeyLength", QString::number(keyMaker.keyLength()));
        xml.writeTextElement("Cipher", cipher.algorithmName());
        xml.writeTextElement("Method", cipher.operationCode());
        xml.writeTextElement("InitialVector", QString::fromLatin1(cipher.initialVector().toHex()));
        xml.writeEndElement();

        xml.writeStartElement("Payload");

        for (Qrypto::Pointerator<const char> it(crypt.constData(), crypt.size()), chunk; !it.atEnd(); ) {
            QString text;
            chunk = it.read(524288);
            text.reserve(chunk.size() * 8 / 6 + chunk.size() / 180);

            for (Qrypto::Pointerator<const char> end = chunk.end(), line; chunk != end; ) {
                line = chunk.read(180);
                text += QChar('\n');
                text += QString::fromLatin1(QByteArray(line.data(), line.size()).toBase64());
            }

            xml.writeTextElement("Data", text);
        }

        xml.writeEndElement();

        xml.writeStartElement("Trailer");
        xml.writeTextElement("Length", QString::number(plain.size()));
        xml.writeTextElement("Authentication", QString::fromLatin1(cipher.authentication().toHex()));
        xml.writeTextElement("Compression", compress.algorithmName());
        xml.writeEndElement();

        xml.writeEndDocument();
        return !xml.hasError();
    }
};

const QStringList QryptIO::Private::CrypticV1 =
        QStringList() << "/Header/Digest" << "/Header/Salt" << "/Header/IterationCount" <<
                         "/Header/KeyLength" << "/Header/Cipher" << "/Header/Method" <<
                         "/Header/InitVector" << "/Payload/Data" << "/Payload/HexData" <<
                         "/Trailer/Length";

const QStringList QryptIO::Private::CrypticV2 =
        QStringList() << "/Header/Digest" << "/Header/Salt" << "/Header/IterationCount" <<
                         "/Header/KeyLength" << "/Header/Cipher" << "/Header/Method" <<
                         "/Header/InitialVector" << "/Payload/Data" << "/Payload/HexData" <<
                         "/Trailer/Length" << "/Trailer/Authentication" << "/Trailer/Compression";

QryptIO::QryptIO(QIODevice *device) :
    d(new Private(device))
{ }

QryptIO::~QryptIO()
{
    delete d;
}

int QryptIO::crypticVersion()
{
    if (d->crypticVersion == -1 && d->isReadable()) {
        QByteArray peek(d->device->peek(512));
        QXmlStreamReader xml(peek);

        if (xml.readNextStartElement() && xml.name() == "Cryptic") {
            foreach (const QXmlStreamAttribute &attr, xml.attributes()) {
                if (attr.name() == "schemaVersion")
                    d->crypticVersion = attr.value().toInt();
            }

            if (d->crypticVersion < 1 || d->crypticVersion > 2)
                d->crypticVersion = -2;
        } else {
            d->crypticVersion = 0;
        }
    }

    return d->crypticVersion;
}

Qrypto::Cipher &QryptIO::cipher()
{
    return d->cipher;
}

Qrypto::Compress &QryptIO::compress()
{
    return d->compress;
}

QryptIO::Status QryptIO::decrypt(QByteArray &data, const QString &password)
{
    d->error = Qrypto::NoError;
    d->status = Ok;
    data.clear();

    if (d->isReadable() || !d->crypt.isEmpty()) {
        Qrypto::SequreBytes sequre(password.toUtf8());

        switch (crypticVersion()) {
        case 0: // non-cryptic
            if (!d->device->atEnd())
                d->device->readAll().swap(d->crypt);

            data = d->crypt;

            if (data.isNull())
                d->status = ReadCorruptData;

            break;
        case 1:
            if (!d->crypt.isEmpty() || d->loadV1()) {
                d->error = d->keyMaker.deriveKey(*sequre, d->cipher.validateKeyLength(d->keyMaker.keyLength()));

                if (d->error) {
                    d->status = KeyDerivationError;
                } else {
                    d->plain.resize(0);
                    d->error = d->cipher.decrypt(d->plain, d->crypt, d->keyMaker);

                    if (d->error) {
                        d->status = CryptographicError;
                    } else if (d->plain->startsWith("<!DOCTYPE HTML ")) {
                        d->plain->swap(data);
                    } else {
                        d->error = Qrypto::IntegrityError;
                        d->status = CryptographicError;
                    }
                }
            } else {
                d->status = ReadCorruptData;
            }

            break;
        case 2:
            if (!d->crypt.isEmpty() || d->loadV2()) {
                d->error = d->keyMaker.deriveKey(*sequre, d->cipher.validateKeyLength(d->keyMaker.keyLength()));

                if (d->error) {
                    d->status = KeyDerivationError;
                } else {
                    d->plain.resize(0);
                    d->error = d->cipher.decrypt(d->plain, d->crypt, d->keyMaker);

                    if (d->error) {
                        d->status = CryptographicError;
                    } else {
                        sequre.reserve(d->plain.capacity());
                        sequre.resize(0);
                        d->error = d->compress.inflate(sequre, *d->plain);

                        if (d->error)
                            d->status = CompressionError;
                        else
                            sequre->swap(data);
                    }
                }
            } else {
                d->status = ReadCorruptData;
            }

            break;
        default:
            d->status = ReadCorruptData;
        }
    } else {
        d->status = ReadPastEnd;
    }

    return d->status;
}

QIODevice *QryptIO::device() const
{
    return d->device;
}

QryptIO::Status QryptIO::encrypt(const QByteArray &data, const QString &password)
{
    d->error = Qrypto::NoError;
    d->status = WriteFailed;

    if (d->isWritable()) {
        if (password.isEmpty()) {
            if (d->device->write(data) == data.size())
                d->status = Ok;
        } else {
            const Qrypto::SequreBytes pwd(password.toUtf8());
            d->error = d->keyMaker.deriveKey(*pwd, d->cipher.validateKeyLength(d->keyMaker.keyLength()));

            if (d->error) {
                d->status = KeyDerivationError;
            } else {
                d->error = d->compress.deflate(d->plain, data);

                if (d->error) {
                    d->status = CompressionError;
                } else {
                    d->error = d->cipher.encrypt(d->crypt, d->plain, d->keyMaker);

                    if (d->error) {
                        d->status = CryptographicError;
                    } else {
                        d->crypticVersion = 2;
                        d->plain.resize(data.size()); // plain length will be saved

                        if (d->save())
                            d->status = Ok;
                    }
                }
            }
        }
    }

    return d->status;
}

Qrypto::Error QryptIO::error() const
{
    return d->error;
}

Qrypto::KeyMaker &QryptIO::keyMaker()
{
    return d->keyMaker;
}

QryptIO::Status QryptIO::status() const
{
    return d->status;
}
