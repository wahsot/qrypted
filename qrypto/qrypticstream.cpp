#include "qrypticstream.h"

#include <QXmlStreamReader>
#include <QXmlStreamWriter>

#include <cryptopp/base64.h>
#include <cryptopp/camellia.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/idea.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/rijndael.h>
#include <cryptopp/secblock.h>
#include <cryptopp/serpent.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/twofish.h>

/* Welcome to C++ where we fight templates with more templates */

template <template <typename T> class KeyDerivation>
struct PBKDF_Class
{
    CryptoPP::PasswordBasedKeyDerivationFunction *operator()(QrypticStream::Digest digest)
    {
        switch (digest) {
        case QrypticStream::Sha1:
            return new KeyDerivation<CryptoPP::SHA1>;
        case QrypticStream::Sha256:
            return new KeyDerivation<CryptoPP::SHA256>;
        case QrypticStream::Sha512:
            return new KeyDerivation<CryptoPP::SHA512>;
        case QrypticStream::Sha3_256:
            return new KeyDerivation<CryptoPP::SHA3_256>;
        case QrypticStream::Sha3_512:
            return new KeyDerivation<CryptoPP::SHA3_512>;
        default:
            return 0;
        }
    }
};

struct QrypticStream::Private
{
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock key;
    CryptoPP::SecByteBlock password;
    CryptoPP::SecByteBlock IV;
    CryptoPP::SecByteBlock salt;
    QrypticStream::Settings settings;
    QIODevice *device;

    Private(QIODevice *device) :
        device(device)
    { }

    ~Private()
    {
    }

    bool createKey()
    {
        if (key.empty()) {
            QScopedPointer<CryptoPP::PasswordBasedKeyDerivationFunction> PBKDF;

            switch (settings.keyDerivation) {
            case QrypticStream::PKCS5_PBKDF1:
                PBKDF.reset(PBKDF_Class<CryptoPP::PKCS5_PBKDF1>()(settings.digest));
                break;
            case QrypticStream::PKCS5_PBKDF2_HMAC:
                PBKDF.reset(PBKDF_Class<CryptoPP::PKCS5_PBKDF2_HMAC>()(settings.digest));
                break;
                /* CANNOT COMPILE
            case QrypticStream::PKCS12_PBKDF:
                PBKDF.reset(PBKDF_Class<CryptoPP::PKCS12_PBKDF>()(settings.digest));
                break;
                */
            default:
                break;
            }

            switch (settings.cipher) {
            case QrypticStream::IDEA:
                key.resize(CryptoPP::IDEA::DEFAULT_KEYLENGTH);
                break;
            case QrypticStream::Blowfish:
                key.resize(CryptoPP::Blowfish::DEFAULT_KEYLENGTH);
                break;
            case QrypticStream::Camellia:
                key.resize(CryptoPP::Camellia::DEFAULT_KEYLENGTH);
                break;
            case QrypticStream::Rijndael:
                key.resize(CryptoPP::Rijndael::DEFAULT_KEYLENGTH);
                break;
            case QrypticStream::Serpent:
                key.resize(CryptoPP::Serpent::DEFAULT_KEYLENGTH);
                break;
            case QrypticStream::Twofish:
                key.resize(CryptoPP::Twofish::DEFAULT_KEYLENGTH);
                break;
            default:
                break;
            }

            if (PBKDF.isNull() || key.empty()) return false;

            if (salt.empty()) {
                salt.resize(settings.saltLength);
                prng.GenerateBlock(salt.data(), salt.size());
            }

            Q_ASSERT(settings.iterations > 0);
            PBKDF->DeriveKey(key.data(), key.size(), 0,
                             password.data(), password.size(),
                             salt.data(), salt.size(), settings.iterations);
        }

        return true;
    }

    /*
    template <class Method>
    CryptoPP::StreamTransformation *decryption()
    {
        using namespace QrypticStream;
        switch (settings.cipher) {
        case IDEA:
            return new Method<CryptoPP::IDEA>::Decryption;
        case Blowfish:
            return new Method<CryptoPP::Blowfish>::Decryption;
        case Camellia:
            return new Method<CryptoPP::Camellia>::Decryption;
        case Rijndael:
            return new Method<CryptoPP::Rijndael>::Decryption;
        case Serpent:
            return new Method<CryptoPP::Serpent>::Decryption;
        case Twofish:
            return new Method<CryptoPP::Twofish>::Decryption;
        default:
            return 0;
        }
    }
    */
};

template <template <typename T> class Method>
struct Cipher_Class
{
    QrypticStream::Private *d;

    Cipher_Class(QrypticStream::Private *d) : d(d) { }

    CryptoPP::StreamTransformation *encrypt()
    {
        //CryptoPP::CBC_Mode<CryptoPP::IDEA>::Encryption e;
        //e.SetCipherWithIV();
        switch (d->settings.cipher) {
        case QrypticStream::IDEA:
            d->IV.resize(CryptoPP::IDEA::IV_REQUIREMENT);
            d->prng.GenerateBlock(d->IV.data(), d->IV.size());
            return new typename Method<CryptoPP::IDEA>::Encryption(d->key.data(), d->key.size(), d->IV.data());
        case QrypticStream::Blowfish:
            d->IV.resize(CryptoPP::Blowfish::IV_REQUIREMENT);
            d->prng.GenerateBlock(d->IV.data(), d->IV.size());
            return new typename Method<CryptoPP::Blowfish>::Encryption(d->key.data(), d->key.size(), d->IV.data());
        case QrypticStream::Camellia:
            d->IV.resize(CryptoPP::Camellia::IV_REQUIREMENT);
            d->prng.GenerateBlock(d->IV.data(), d->IV.size());
            return new typename Method<CryptoPP::Camellia>::Encryption(d->key.data(), d->key.size(), d->IV.data());
        case QrypticStream::Rijndael:
            d->IV.resize(CryptoPP::Rijndael::IV_REQUIREMENT);
            d->prng.GenerateBlock(d->IV.data(), d->IV.size());
            return new typename Method<CryptoPP::Rijndael>::Encryption(d->key.data(), d->key.size(), d->IV.data());
        case QrypticStream::Serpent:
            d->IV.resize(CryptoPP::Serpent::IV_REQUIREMENT);
            d->prng.GenerateBlock(d->IV.data(), d->IV.size());
            return new typename Method<CryptoPP::Serpent>::Encryption(d->key.data(), d->key.size(), d->IV.data());
        case QrypticStream::Twofish:
            d->IV.resize(CryptoPP::Twofish::IV_REQUIREMENT);
            d->prng.GenerateBlock(d->IV.data(), d->IV.size());
            return new typename Method<CryptoPP::Twofish>::Encryption(d->key.data(), d->key.size(), d->IV.data());
        default:
            return 0;
        }
    }
};

const QStringList QrypticStream::Ciphers = QStringList() << "IDEA" << "Blowfish" << "Camellia" <<
                                                            "Rijndael" << "Serpent" << "Twofish" <<
                                                            QString();

const QStringList QrypticStream::Digests = QStringList() << "Sha1" << "Sha2-256" << "Sha2-512" <<
                                                            "Sha3-256" << "Sha3-512" <<
                                                            QString();

const QStringList QrypticStream::Methods = QStringList() << "ECB" << "CBC" << "CFB" << "OFB" << "CTR" <<
                                                            QString();

QrypticStream::QrypticStream(QIODevice *device) :
    QObject(device),
    d(new Private(device))
{

}

QrypticStream::~QrypticStream()
{
    delete d;
}

QIODevice *QrypticStream::device() const
{
    return d->device;
}

bool QrypticStream::encrypt(const QByteArray &src)
{
    if (d->device && d->createKey()) {
        QScopedPointer<CryptoPP::StreamTransformation> cipher;
        std::string sink;

        switch (d->settings.method) {
        case ElectronicCodebook:
            cipher.reset(Cipher_Class<CryptoPP::ECB_Mode>(d).encrypt());
            break;
        case CipherBlockChaining:
            cipher.reset(Cipher_Class<CryptoPP::CBC_Mode>(d).encrypt());
            break;
        case CipherFeedback:
            cipher.reset(Cipher_Class<CryptoPP::CFB_Mode>(d).encrypt());
            break;
        case OutputFeedback:
            cipher.reset(Cipher_Class<CryptoPP::OFB_Mode>(d).encrypt());
            break;
        case Counter:
            cipher.reset(Cipher_Class<CryptoPP::CTR_Mode>(d).encrypt());
            break;
        default:
            break;
        }

        if (cipher.isNull()) return false;

        using namespace CryptoPP;

        StringSource(src.toStdString(), true,
                     new StreamTransformationFilter(*cipher,
                                                    new Base64Encoder(new StringSink(sink))));

        if (d->device->isWritable() || d->device->open(QIODevice::WriteOnly)) {
            QXmlStreamWriter stream(d->device);
            stream.setAutoFormatting(true);
            stream.setAutoFormattingIndent(-1);
            stream.writeStartDocument();
            stream.writeStartElement("cryptic.xsd", "Cryptic");
            stream.writeStartElement("Header");
            stream.writeTextElement("Salt",
                                    QByteArray::fromRawData(reinterpret_cast<char*>(d->salt.data()),
                                                            d->salt.size()).toHex());
            stream.writeTextElement("Iterations", QString::number(d->settings.iterations));
            stream.writeTextElement("Digest", Digests.at(d->settings.digest));
            stream.writeTextElement("OperationMode", Methods.at(d->settings.method));
            stream.writeTextElement("Cipher", Ciphers.at(d->settings.cipher));
            stream.writeTextElement("InitializationVector",
                                    QByteArray::fromRawData(reinterpret_cast<char*>(d->IV.data()),
                                                            d->IV.size()).toHex());
            stream.writeEndElement();
            stream.writeStartElement("Payload");
            stream.writeTextElement("Data", QString::fromStdString(sink));
            stream.writeEndElement();
            stream.writeStartElement("Trailer");
            stream.writeTextElement("Length", QString::number(src.size()));
            stream.writeEndDocument();

            return true;
        }
    }

    return false;
}

void QrypticStream::setDevice(QIODevice *device)
{
    delete d;
    d = new Private(device);
}

void QrypticStream::setPassword(const QString &plain)
{
    const QByteArray password = plain.toUtf8();
    d->password.resize(password.size());
    memcpy(d->password.data(), password.constData(), password.size());
}

void QrypticStream::setSettings(const Settings &settings)
{
    int i = settings.cipher;

    if (i < 0 || UnknownCipher <= i)
        return;
    else
        i = settings.digest;

    if (i < 0 || UnknownDigest <= i)
        return;
    else
        d->settings = settings;
}

const QrypticStream::Settings &QrypticStream::settings() const
{
    return d->settings;
}
