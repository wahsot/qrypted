#include "qryptocipher.h"

#include <QVariant>

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
#include <cryptopp/seed.h>
#include <cryptopp/serpent.h>
#include <cryptopp/sha.h>
#include <cryptopp/twofish.h>

namespace QryptoPP
{

template <typename Alg>
struct Cipher::Action
{
    Cipher *d;
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock key;

    Action(Cipher *d, const QByteArray &password) :
        d(d),
        key(Alg::StaticGetValidKeyLength(d->m_keyLength))
    {
        const QByteArray Zero(d->m_salt.size(), 0);
        byte *saltData = reinterpret_cast<byte*>(d->m_salt.data());
        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA1> PBKDF;
        d->m_keyLength = key.size();

        if (std::memcmp(Zero.data(), saltData, d->m_salt.size()) == 0)
            prng.GenerateBlock(saltData, d->m_salt.size());

        PBKDF.DeriveKey(key.data(), key.size(), 0,
                        reinterpret_cast<const byte*>(password.constData()), password.size(),
                        saltData, d->m_salt.size(), d->m_iteration);
    }

    ~Action() { }

    CryptoPP::StreamTransformation *getDecryption() const
    {
        const byte *IVData = reinterpret_cast<const byte*>(d->m_IV.constData());

        switch (d->m_operation) {
        case Cipher::CBC:
            return new typename CryptoPP::CBC_Mode<Alg>::Decryption(key.data(), key.size(), IVData, d->m_IV.size());
        case Cipher::CFB:
            return new typename CryptoPP::CFB_Mode<Alg>::Decryption(key.data(), key.size(), IVData, d->m_IV.size());
        case Cipher::CTR:
            return new typename CryptoPP::CTR_Mode<Alg>::Decryption(key.data(), key.size(), IVData, d->m_IV.size());
        case Cipher::ECB:
            return new typename CryptoPP::ECB_Mode<Alg>::Decryption(key.data(), key.size(), IVData, d->m_IV.size());
        case Cipher::OFB:
            return new typename CryptoPP::OFB_Mode<Alg>::Decryption(key.data(), key.size(), IVData, d->m_IV.size());
        default:
            return 0;
        }
    }

    CryptoPP::StreamTransformation *getEncryption() const
    {
        const byte *IVData = reinterpret_cast<const byte*>(d->m_IV.constData());

        switch (d->m_operation) {
        case Cipher::CBC:
            return new typename CryptoPP::CBC_Mode<Alg>::Encryption(key.data(), key.size(), IVData, d->m_IV.size());
        case Cipher::CFB:
            return new typename CryptoPP::CFB_Mode<Alg>::Encryption(key.data(), key.size(), IVData, d->m_IV.size());
        case Cipher::CTR:
            return new typename CryptoPP::CTR_Mode<Alg>::Encryption(key.data(), key.size(), IVData, d->m_IV.size());
        case Cipher::ECB:
            return new typename CryptoPP::ECB_Mode<Alg>::Encryption(key.data(), key.size(), IVData, d->m_IV.size());
        case Cipher::OFB:
            return new typename CryptoPP::OFB_Mode<Alg>::Encryption(key.data(), key.size(), IVData, d->m_IV.size());
        default:
            return 0;
        }
    }

    bool decrypt(QByteArray &dst, const QByteArray &src)
    {
        using namespace CryptoPP;
        QScopedPointer<StreamTransformation> cipher(getDecryption());
        std::string sink;

        if (cipher.isNull()) return false;

        try {
            StringSource(src.toStdString(), true,
                         new StreamTransformationFilter(*cipher, new StringSink(sink)));
            dst.resize(sink.size());
            std::memcpy(dst.data(), sink.data(), sink.size());
        } catch (...) {
            return false;
        }

        return true;
    }

    bool encrypt(QByteArray &dst, const QByteArray &src)
    {
        using namespace CryptoPP;
        QScopedPointer<StreamTransformation> cipher;
        std::string sink;
        d->m_IV.resize(Alg::BLOCKSIZE);
        prng.GenerateBlock(reinterpret_cast<byte*>(d->m_IV.data()), d->m_IV.size());
        cipher.reset(getEncryption());

        if (cipher.isNull()) return false;

        try {
            StringSource(src.toStdString(), true,
                         new StreamTransformationFilter(*cipher, new StringSink(sink)));
            dst.resize(sink.size());
            std::memcpy(dst.data(), sink.data(), sink.size());
        } catch (...) {
            return false;
        }

        return true;
    }
};

}

using namespace QryptoPP;

bool Cipher::canDecrypt() const
{
    if (canEncrypt()) {
        const QByteArray Zero(std::max(m_salt.size(), m_IV.size()), 0);
        return std::memcmp(Zero.constData(), m_salt.constData(), m_salt.size()) &&
                std::memcmp(Zero.constData(), m_IV.constData(), m_IV.size());
    } else {
        return false;
    }
}

bool Cipher::canEncrypt() const
{
    return m_iteration && m_salt.size() > 7 && m_IV.size() > 7 &&
            m_algorithm < UnknownAlgorithm && m_operation < UnknownOperation;
}

bool Cipher::decrypt(QByteArray &dst, const QByteArray &password, const QByteArray &src)
{
    if (canDecrypt()) {
        switch (m_algorithm) {
        case AES:
            return Action<CryptoPP::AES>(this, password).decrypt(dst, src);
        case Blowfish:
            return Action<CryptoPP::Blowfish>(this, password).decrypt(dst, src);
        case Camellia:
            return Action<CryptoPP::Camellia>(this, password).decrypt(dst, src);
        case IDEA:
            return Action<CryptoPP::IDEA>(this, password).decrypt(dst, src);
        case SEED:
            return Action<CryptoPP::SEED>(this, password).decrypt(dst, src);
        case Serpent:
            return Action<CryptoPP::Serpent>(this, password).decrypt(dst, src);
        case Twofish:
            return Action<CryptoPP::Twofish>(this, password).decrypt(dst, src);
        default:
            break;
        }
    }

    return false;
}

bool Cipher::encrypt(QByteArray &dst, const QByteArray &password, const QByteArray &src)
{
    if (canEncrypt()) {
        switch (m_algorithm) {
        case AES:
            return Action<CryptoPP::AES>(this, password).encrypt(dst, src);
        case Blowfish:
            return Action<CryptoPP::Blowfish>(this, password).encrypt(dst, src);
        case Camellia:
            return Action<CryptoPP::Camellia>(this, password).encrypt(dst, src);
        case IDEA:
            return Action<CryptoPP::IDEA>(this, password).encrypt(dst, src);
        case SEED:
            return Action<CryptoPP::SEED>(this, password).encrypt(dst, src);
        case Serpent:
            return Action<CryptoPP::Serpent>(this, password).encrypt(dst, src);
        case Twofish:
            return Action<CryptoPP::Twofish>(this, password).encrypt(dst, src);
        default:
            break;
        }
    }

    return false;
}
