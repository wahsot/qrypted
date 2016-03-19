#include "qrypticstream.h"

#include <QVariant>
#include <QXmlStreamReader>
#include <QXmlStreamWriter>

#include "qryptocipher.h"
#include "qryptokeymaker.h"

struct QryptIO::Private
{
    QryptoPP::Cipher cipher;
    QIODevice *device;
    int crypticVersion;

    Private(QIODevice *device) :
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

    bool load(QByteArray &crypt)
    {
        QryptoPP::KeyMaker &keyMaker = cipher.keyMaker();
        QXmlStreamReader xml(device);
        QStringList Elements;
        Elements << "/Header/Digest" << "/Header/Salt" << "/Header/IterationCount" <<
                    "/Header/KeyLength" << "/Header/Cipher" << "/Header/Method" <<
                    "/Header/InitVector" << "/Payload/Data" << "/Payload/HexData" << "/Trailer/Length";
        int from = 0;
        int length = 0;
        crypt.resize(0);

        if (!xml.readNextStartElement())
            return false;

        for (QString path; !xml.atEnd(); ) {
            switch (xml.readNext()) {
            case QXmlStreamReader::StartElement:
                path += "/";
                path += xml.name();
                //qDebug() << path << from;

                switch (Elements.indexOf(path, from)) {
                case 0: keyMaker.setAlgorithmName(xml.readElementText()); break;
                case 1: keyMaker.setSalt(xml.readElementText()); break;
                case 2: keyMaker.setIterationCount(xml.readElementText().toUInt()); break;
                case 3: cipher.setKeyLength(xml.readElementText().toUInt()); break;
                case 4: cipher.setAlgorithmName(xml.readElementText()); break;
                case 5: cipher.setOperationCode(xml.readElementText()); break;
                case 6: cipher.setInitVector(xml.readElementText()); break;
                case 7: crypt += QByteArray::fromBase64(xml.readElementText().toLatin1()); break;
                case 8: crypt += QByteArray::fromHex(xml.readElementText().toLatin1()); break;
                case 9: length = xml.readElementText().toUInt(); break;
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

    bool save(const QByteArray &crypt)
    {
        const QryptoPP::KeyMaker &keyMaker = cipher.keyMaker();
        QXmlStreamWriter xml(device);
        xml.setAutoFormatting(true);
        xml.setAutoFormattingIndent(-1);

        xml.writeStartDocument();
        xml.writeStartElement("cryptic.xsd", "Cryptic");
        xml.writeAttribute("schemaVersion", QString::number(crypticVersion));

        xml.writeStartElement("Header");
        xml.writeTextElement("Digest", keyMaker.algorithmName());
        xml.writeTextElement("Salt", keyMaker.salt().toHex());
        xml.writeTextElement("IterationCount", QString::number(keyMaker.iterationCount()));
        xml.writeTextElement("KeyLength", QString::number(cipher.keyLength()));
        xml.writeTextElement("Cipher", cipher.algorithmName());
        xml.writeTextElement("Method", cipher.operationCode());
        xml.writeTextElement("InitVector", cipher.initVector().toHex());
        xml.writeEndElement();

        xml.writeStartElement("Payload");
        xml.writeTextElement("Data", crypt.toBase64());
        xml.writeEndElement();

        xml.writeStartElement("Trailer");
        xml.writeTextElement("Length", QString::number(crypt.size()));
        xml.writeEndElement();

        xml.writeEndDocument();
        return !xml.hasError();
    }
};

QryptIO::QryptIO(QIODevice *device) :
    d(new Private(device))
{
}

QryptIO::~QryptIO()
{
    delete d;
}

int QryptIO::crypticVersion()
{
    if (d->crypticVersion == -1 && d->isReadable()) {
        QByteArray peek(d->device->peek(512));
        QXmlStreamReader xml(peek);
        d->crypticVersion = 0;

        if (xml.readNextStartElement() && xml.name() == "Cryptic") {
            foreach (const QXmlStreamAttribute &attr, xml.attributes()) {
                if (attr.name() == "schemaVersion")
                    d->crypticVersion = std::max(0, attr.value().toInt());
            }
        }
    }

    return d->crypticVersion;
}

QryptIO::Status QryptIO::read(QByteArray &data, const QString &password)
{
    if (d->isReadable()) {
        switch (crypticVersion()) {
        case -1:
            return ReadPastEnd;
        case 0:
            d->device->readAll().swap(data);
            break;
        case 1:
            if (!password.isEmpty()) {
                QByteArray crypt;

                if (d->load(crypt)) {
                    if (d->cipher.decrypt(data, crypt, password.toUtf8()))
                        return Ok;
                } else {
                    data.clear();
                    break;
                }
            }
        default:
            data.clear();
            return DecryptionFailed;
        }

        if (data.isNull())
            return ReadCorruptData;
        else
            return Ok;
    }

    return ReadPastEnd;
}

QryptIO::Status QryptIO::write(const QByteArray &data, const QString &password)
{
    if (d->isWritable()) {
        if (password.isNull()) {
            if (d->device->write(data) == data.size())
                return Ok;
        } else {
            QByteArray crypt;
            d->crypticVersion = 1;

            if (d->cipher.encrypt(crypt, data, password.toUtf8())) {
                if (d->save(crypt))
                    return Ok;
            } else {
                return EncryptionFailed;
            }
        }
    }

    return WriteFailed;
}

QryptoPP::Cipher &QryptIO::cipher()
{
    return d->cipher;
}

QryptoPP::KeyMaker &QryptIO::keyMaker()
{
    return d->cipher.keyMaker();
}
