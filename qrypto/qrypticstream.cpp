#include "qrypticstream.h"

#include <QXmlStreamReader>
#include <QXmlStreamWriter>

#include <cryptopp/camellia.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/filters.h>
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
    CryptoPP::SecByteBlock salt;
    CryptoPP::SecByteBlock password;
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

            if (PBKDF.isNull()) return false;

            if (salt.empty()) {
                salt.resize(settings.saltLength);
                prng.GenerateBlock(salt.data(), salt.size());
            }

            Q_ASSERT(settings.iterations > 0);
            key.resize(PBKDF->MaxDerivedKeyLength());
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
        CryptoPP::SecByteBlock iv;

        switch (d->settings.cipher) {
        case QrypticStream::IDEA:
            iv.resize(CryptoPP::IDEA::IV_LENGTH);
            d->prng.GenerateBlock(iv.data(), iv.size());
            return new typename Method<CryptoPP::IDEA>::Encryption(d->key.data(), d->key.size(), iv.data());
        case QrypticStream::Blowfish:
            iv.resize(CryptoPP::Blowfish::IV_LENGTH);
            d->prng.GenerateBlock(iv.data(), iv.size());
            return new typename Method<CryptoPP::Blowfish>::Encryption(d->key.data(), d->key.size(), iv.data());
        case QrypticStream::Camellia:
            iv.resize(CryptoPP::Camellia::IV_LENGTH);
            d->prng.GenerateBlock(iv.data(), iv.size());
            return new typename Method<CryptoPP::Camellia>::Encryption(d->key.data(), d->key.size(), iv.data());
        case QrypticStream::Rijndael:
            iv.resize(CryptoPP::Rijndael::IV_LENGTH);
            d->prng.GenerateBlock(iv.data(), iv.size());
            return new typename Method<CryptoPP::Rijndael>::Encryption(d->key.data(), d->key.size(), iv.data());
        case QrypticStream::Serpent:
            iv.resize(CryptoPP::Serpent::IV_LENGTH);
            d->prng.GenerateBlock(iv.data(), iv.size());
            return new typename Method<CryptoPP::Serpent>::Encryption(d->key.data(), d->key.size(), iv.data());
        case QrypticStream::Twofish:
            iv.resize(CryptoPP::Twofish::IV_LENGTH);
            d->prng.GenerateBlock(iv.data(), iv.size());
            return new typename Method<CryptoPP::Twofish>::Encryption(d->key.data(), d->key.size(), iv.data());
        default:
            return 0;
        }
    }
};

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

        CryptoPP::StringSource(src.toStdString(), true,
                               new CryptoPP::StreamTransformationFilter(*cipher,
                                                                        new CryptoPP::StringSink(sink)));

        if (d->device->isWritable() || d->device->open(QIODevice::WriteOnly)) {
            QXmlStreamWriter stream(d->device);
            stream.setAutoFormattingIndent(-1);
            stream.writeStartDocument();
        }
    }
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
