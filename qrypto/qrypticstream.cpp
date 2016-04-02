#include "qrypticstream.h"

#include <QXmlStreamReader>
#include <QXmlStreamWriter>

#include "pointerator.h"
#include "qryptocipher.h"
#include "qryptocompress.h"
#include "qryptokeymaker.h"

struct QryptIO::Private
{
    static const QStringList CrypticV1;
    static const QStringList CrypticV2;
    Qrypto::Error error;
    QryptIO::Status status;
    QIODevice *device;
    int crypticVersion;
    uint plainLength;
    Qrypto::Compress compress;
    Qrypto::Cipher cipher;

    Private(QIODevice *device) :
        error(Qrypto::NoError),
        status(QryptIO::Ok),
        device(device),
        crypticVersion(-1),
        plainLength(0)
    { }

    bool isReadable()
    {
        return device && (device->isReadable() || device->open(QIODevice::ReadOnly)) && !device->atEnd();
    }

    bool isWritable()
    {
        return device && (device->isWritable() || device->open(QIODevice::WriteOnly));
    }

    bool loadV1(QByteArray &crypt)
    {
        Q_ASSERT(crypticVersion > 0);
        Qrypto::KeyMaker &keyMaker = cipher.keyMaker();
        QXmlStreamReader xml(device);
        int from = 0;
        crypt.resize(0);

        if (!xml.readNextStartElement())
            return false;

        for (QString path; !xml.atEnd(); ) {
            switch (xml.readNext()) {
            case QXmlStreamReader::StartElement:
                path += "/";
                path += xml.name();

                switch (CrypticV1.indexOf(path, from)) {
                case 0: keyMaker.setAlgorithmName(xml.readElementText()); break;
                case 1: keyMaker.setSalt(xml.readElementText()); break;
                case 2: keyMaker.setIterationCount(xml.readElementText().toUInt()); break;
                case 3: cipher.setKeyLength(xml.readElementText().toUInt()); break;
                case 4: cipher.setAlgorithmName(xml.readElementText()); break;
                case 5: cipher.setOperationCode(xml.readElementText()); break;
                case 6: cipher.setInitialVector(xml.readElementText()); break;
                case 7: crypt += QByteArray::fromBase64(xml.readElementText().toLatin1()); break;
                case 8: crypt += QByteArray::fromHex(xml.readElementText().toLatin1()); break;
                case 9: plainLength = xml.readElementText().toUInt(); break;
                default:
                    continue;
                }

                ++from;
            case QXmlStreamReader::EndElement:
                path = path.section('/', 0, -2);
                break;
            default:
                continue;
            }
        }

        return !xml.hasError();
    }

    bool loadV2(QByteArray &crypt)
    {
        Q_ASSERT(crypticVersion > 0);
        Qrypto::KeyMaker &keyMaker = cipher.keyMaker();
        QXmlStreamReader xml(device);
        int from = 0;
        crypt.resize(0);

        if (!xml.readNextStartElement())
            return false;

        for (QString path; !xml.atEnd(); ) {
            switch (xml.readNext()) {
            case QXmlStreamReader::StartElement:
                path += "/";
                path += xml.name();

                switch (CrypticV2.indexOf(path, from)) {
                case  0: keyMaker.setAlgorithmName(xml.readElementText()); break;
                case  1: keyMaker.setSalt(xml.readElementText()); break;
                case  2: keyMaker.setIterationCount(xml.readElementText().toUInt()); break;
                case  3: cipher.setKeyLength(xml.readElementText().toUInt()); break;
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
                case  9: plainLength = xml.readElementText().toUInt(); break;
                case 10: cipher.setAuthentication(xml.readElementText()); break;
                case 11: compress.setAlgorithmName(xml.readElementText()); break;
                default:
                    continue;
                }

                ++from;
            case QXmlStreamReader::EndElement:
                path = path.section('/', 0, -2);
                break;
            default:
                continue;
            }
        }

        return !xml.hasError();
    }

    bool save(const QByteArray &crypt, const QByteArray &plain)
    {
        const Qrypto::KeyMaker &keyMaker = cipher.keyMaker();
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
        xml.writeTextElement("KeyLength", QString::number(cipher.keyLength()));
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

Qrypto::Error QryptIO::error() const
{
    return d->error;
}

QryptIO::Status QryptIO::read(QByteArray &data, const QString &password)
{
    d->error = Qrypto::NoError;
    d->status = ReadPastEnd;
    data.clear();

    if (d->isReadable()) {
        QByteArray crypt;

        switch (crypticVersion()) {
        case 0: // non-cryptic
            d->device->readAll().swap(data);

            if (!data.isNull())
                d->status = Ok;

            break;
        case 1:
            if (d->loadV1(crypt)) {
                d->status = DecryptionFailed;

                if (d->cipher.decrypt(data, crypt, password.toUtf8())) {
                    if (data.startsWith("<!DOCTYPE HTML "))
                        d->status = Ok;
                    else
                        d->error = Qrypto::IntegrityError;
                } else {
                    d->error = d->cipher.error();
                }
            } else {
                d->status = ReadCorruptData;
            }

            break;
        case 2:
            if (d->loadV2(crypt)) {
                QByteArray plain;
                d->status = DecryptionFailed;

                if (d->cipher.decrypt(plain, crypt, password.toUtf8())) {
                    crypt.clear();
                    d->error = d->compress.inflate(data, plain);

                    if (d->error == Qrypto::NoError)
                        d->status = Ok;
                } else {
                    d->error = d->cipher.error();
                }
            } else {
                d->status = ReadCorruptData;
            }

            break;
        default:
            d->status = ReadCorruptData;
        }
    }

    return d->status;
}

QryptIO::Status QryptIO::write(const QByteArray &data, const QString &password)
{
    d->error = Qrypto::NoError;
    d->status = WriteFailed;

    if (d->isWritable()) {
        if (password.isNull()) {
            if (d->device->write(data) == data.size())
                d->status = Ok;
        } else {
            QByteArray crypt, plain;
            d->crypticVersion = 2;
            d->compress.algorithm = Qrypto::Compress::GZip; // TODO: make this configurable

            if (d->compress.deflate(plain, data) != Qrypto::NoError) {
                d->compress.algorithm = Qrypto::Compress::Identity;
                plain = data;
            }

            if (d->cipher.encrypt(crypt, plain, password.toUtf8())) {
                if (d->save(crypt, plain))
                    d->status = Ok;
            } else {
                d->error = d->cipher.error();
                d->status = EncryptionFailed;
            }
        }
    }

    return d->status;
}

Qrypto::Cipher &QryptIO::cipher()
{
    return d->cipher;
}

Qrypto::KeyMaker &QryptIO::keyMaker()
{
    return d->cipher.keyMaker();
}

QryptIO::Status QryptIO::status() const
{
    return d->status;
}
