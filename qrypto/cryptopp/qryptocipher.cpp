#include "../qryptocipher.h"

#include "../qryptokeymaker.h"
#include "../sequre.h"

#include <QScopedPointer>

#include <cryptopp/camellia.h>
#include <cryptopp/cast.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/des.h>
#include <cryptopp/eax.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/idea.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rijndael.h>
#include <cryptopp/secblock.h>
#include <cryptopp/seed.h>
#include <cryptopp/serpent.h>
#include <cryptopp/twofish.h>

#include <ctime>

namespace Qrypto
{

typedef CryptoPP::StringSinkTemplate<SequreBytes> SequreSink;

struct Cipher::Impl
{
    Cipher *q;

    Impl(Cipher *q = 0) : q(q) { }

    Qrypto::Error decrypt(CryptoPP::Algorithm *cipher, SequreBytes &dst, const QByteArray &src, const KeyMaker &keyMaker)
    {
        using namespace CryptoPP;
        SimpleKeyingInterface *keying = dynamic_cast<SimpleKeyingInterface*>(cipher);

        if (keying->IsValidKeyLength(keyMaker.keyLength())) {
            QScopedPointer<SequreSink> sink(new SequreSink(dst));
            StreamTransformation *stream = dynamic_cast<StreamTransformation*>(cipher);
            AuthenticatedSymmetricCipher *authentic = dynamic_cast<AuthenticatedSymmetricCipher*>(stream);
            dst.reserve(src.size());

            if (keying->IVRequirement() == SimpleKeyingInterface::NOT_RESYNCHRONIZABLE) {
                keying->SetKey(keyMaker.keyData(), keyMaker.keyLength());
            } else {
                keying->SetKeyWithIV(keyMaker.keyData(), keyMaker.keyLength(),
                                     reinterpret_cast<const byte*>(q->m_initialVector.constData()),
                                     q->m_initialVector.size());
            }

            if (authentic) {
                StringSource(src.toStdString(), true,
                             new AuthenticatedDecryptionFilter(*authentic, sink.take()));
            } else {
                StringSource(src.toStdString(), true,
                             new StreamTransformationFilter(*stream, sink.take()));

                if (!q->m_authentication.isEmpty() && keyMaker.authenticate(*dst) != q->m_authentication)
                    throw HashVerificationFilter::HashVerificationFailed();
            }

            return NoError;
        } else {
            throw InvalidKeyLength(cipher->AlgorithmName(), keyMaker.keyLength());
        }
    }

    Qrypto::Error encrypt(CryptoPP::Algorithm *cipher, QByteArray &dst, const SequreBytes &src, const KeyMaker &keyMaker)
    {
        using namespace CryptoPP;
        SimpleKeyingInterface *keying = dynamic_cast<SimpleKeyingInterface*>(cipher);

        if (keying->IsValidKeyLength(keyMaker.keyLength())) {
            std::string str;
            QScopedPointer<StringSink> sink(new StringSink(str));
            StreamTransformation *stream = dynamic_cast<StreamTransformation*>(cipher);
            AuthenticatedSymmetricCipher *authentic = dynamic_cast<AuthenticatedSymmetricCipher*>(stream);
            str.reserve(src->size());

            if (keying->IVRequirement() == SimpleKeyingInterface::NOT_RESYNCHRONIZABLE) {
                q->m_initialVector.clear();
                keying->SetKey(keyMaker.keyData(), keyMaker.keyLength());
            } else {
                AutoSeededRandomPool prng;
                q->m_initialVector.resize(keying->IVSize());
                keying->GetNextIV(prng, reinterpret_cast<byte*>(q->m_initialVector.data()));
                keying->SetKeyWithIV(keyMaker.keyData(), keyMaker.keyLength(),
                                     reinterpret_cast<byte*>(q->m_initialVector.data()));
            }

            if (authentic) {
                StringSource(reinterpret_cast<const byte*>(src->constData()), src->size(), true,
                             new AuthenticatedEncryptionFilter(*authentic, sink.take()));
                q->m_authentication.clear();
            } else {
                StringSource(reinterpret_cast<const byte*>(src->constData()), src->size(), true,
                             new StreamTransformationFilter(*stream, sink.take()));
                q->m_authentication = keyMaker.authenticate(*src);
            }

            QByteArray::fromStdString(str).swap(dst);
            return NoError;
        } else {
            throw InvalidKeyLength(cipher->AlgorithmName(), keyMaker.keyLength());
        }
    }

    template <class Alg>
    CryptoPP::StreamTransformation *getDecryption()
    {
        switch (q->operation()) {
        case Cipher::CBC:
            return new typename CryptoPP::CBC_Mode<Alg>::Decryption;
        case Cipher::CFB:
            return new typename CryptoPP::CFB_Mode<Alg>::Decryption;
        case Cipher::CTR:
            return new typename CryptoPP::CTR_Mode<Alg>::Decryption;
        case Cipher::EAX:
            return new typename CryptoPP::EAX<Alg>::Decryption;
        case Cipher::ECB:
            return new typename CryptoPP::ECB_Mode<Alg>::Decryption;
        case Cipher::GCM:
            return new typename CryptoPP::GCM<Alg>::Decryption;
        case Cipher::OFB:
            return new typename CryptoPP::OFB_Mode<Alg>::Decryption;
        default:
            return 0;
        }
    }

    template <class Alg>
    CryptoPP::StreamTransformation *getEncryption()
    {
        switch (q->operation()) {
        case Cipher::CBC:
            return new typename CryptoPP::CBC_Mode<Alg>::Encryption;
        case Cipher::CFB:
            return new typename CryptoPP::CFB_Mode<Alg>::Encryption;
        case Cipher::CTR:
            return new typename CryptoPP::CTR_Mode<Alg>::Encryption;
        case Cipher::EAX:
            return new typename CryptoPP::EAX<Alg>::Encryption;
        case Cipher::ECB:
            return new typename CryptoPP::ECB_Mode<Alg>::Encryption;
        case Cipher::GCM:
            return new typename CryptoPP::GCM<Alg>::Encryption;
        case Cipher::OFB:
            return new typename CryptoPP::OFB_Mode<Alg>::Encryption;
        default:
            return 0;
        }
    }
};

}

using namespace Qrypto;

const QStringList Cipher::AlgorithmNames =
        QStringList() << CryptoPP::AES::StaticAlgorithmName() <<
                         CryptoPP::Blowfish::StaticAlgorithmName() <<
                         CryptoPP::CAST128::StaticAlgorithmName() <<
                         CryptoPP::Camellia::StaticAlgorithmName() <<
                         CryptoPP::DES_EDE3::StaticAlgorithmName() <<
                         CryptoPP::IDEA::StaticAlgorithmName() <<
                         CryptoPP::SEED::StaticAlgorithmName() <<
                         CryptoPP::Serpent::StaticAlgorithmName() <<
                         CryptoPP::Twofish::StaticAlgorithmName() <<
                         QString();

const QStringList Cipher::OperationCodes =
        QStringList() << "CBC" << "CFB" << "CTR" << "EAX" << "ECB" << "GCM" << "OFB" << QString();

Error Cipher::decrypt(SequreBytes &plain, const QByteArray &crypt, const KeyMaker &keyMaker)
{
    QScopedPointer<CryptoPP::Algorithm> cipher;
    Impl f(this);

    switch (algorithm()) {
    case AES:
        cipher.reset(f.getDecryption<CryptoPP::AES>());
        break;
    case Blowfish:
        cipher.reset(f.getDecryption<CryptoPP::Blowfish>());
        break;
    case CAST_128:
        cipher.reset(f.getDecryption<CryptoPP::CAST128>());
        break;
    case Camellia:
        cipher.reset(f.getDecryption<CryptoPP::Camellia>());
        break;
    case DES_EDE3:
        cipher.reset(f.getDecryption<CryptoPP::DES_EDE3>());
        break;
    case IDEA:
        cipher.reset(f.getDecryption<CryptoPP::IDEA>());
        break;
    case SEED:
        cipher.reset(f.getDecryption<CryptoPP::SEED>());
        break;
    case Serpent:
        cipher.reset(f.getDecryption<CryptoPP::Serpent>());
        break;
    case Twofish:
        cipher.reset(f.getDecryption<CryptoPP::Twofish>());
        break;
    default:
        break;
    }

    if (cipher.isNull())
        return NotImplemented;

    try {
        return f.decrypt(cipher.data(), plain, crypt, keyMaker);
    } catch (const std::bad_alloc &exc) {
        return OutOfMemory;
    } catch (const CryptoPP::Exception &exc) {
        qCritical(exc.what());

        switch (exc.GetErrorType()) {
        case CryptoPP::Exception::NOT_IMPLEMENTED:
            return NotImplemented;
        case CryptoPP::Exception::INVALID_ARGUMENT:
            return InvalidArgument;
        case CryptoPP::Exception::DATA_INTEGRITY_CHECK_FAILED:
            return IntegrityError;
        case CryptoPP::Exception::INVALID_DATA_FORMAT:
            return InvalidFormat;
        default:
            return UnknownError;
        }
    }
}

Error Cipher::encrypt(QByteArray &crypt, const SequreBytes &plain, const KeyMaker &keyMaker)
{
    QScopedPointer<CryptoPP::Algorithm> cipher;
    Impl f(this);

    switch (algorithm()) {
    case AES:
        cipher.reset(f.getEncryption<CryptoPP::AES>());
        break;
    case Blowfish:
        cipher.reset(f.getEncryption<CryptoPP::Blowfish>());
        break;
    case CAST_128:
        cipher.reset(f.getEncryption<CryptoPP::CAST128>());
        break;
    case Camellia:
        cipher.reset(f.getEncryption<CryptoPP::Camellia>());
        break;
    case DES_EDE3:
        cipher.reset(f.getEncryption<CryptoPP::DES_EDE3>());
        break;
    case IDEA:
        cipher.reset(f.getEncryption<CryptoPP::IDEA>());
        break;
    case SEED:
        cipher.reset(f.getEncryption<CryptoPP::SEED>());
        break;
    case Serpent:
        cipher.reset(f.getEncryption<CryptoPP::Serpent>());
        break;
    case Twofish:
        cipher.reset(f.getEncryption<CryptoPP::Twofish>());
        break;
    default:
        break;
    }

    if (cipher.isNull())
        return NotImplemented;

    try {
        return f.encrypt(cipher.data(), crypt, plain, keyMaker);
    } catch (const std::bad_alloc &exc) {
        return OutOfMemory;
    } catch (const CryptoPP::Exception &exc) {
        qCritical(exc.what());

        switch (exc.GetErrorType()) {
        case CryptoPP::Exception::NOT_IMPLEMENTED:
            return NotImplemented;
        case CryptoPP::Exception::INVALID_ARGUMENT:
            return InvalidArgument;
        default:
            return UnknownError;
        }
    }
}

uint Cipher::validateKeyLength(uint keyLength)
{
    switch (algorithm()) {
    case AES:
        return CryptoPP::Rijndael_Info::StaticGetValidKeyLength(keyLength);
    case Blowfish:
        return CryptoPP::Blowfish_Info::StaticGetValidKeyLength(keyLength);
    case CAST_128:
        return CryptoPP::CAST128_Info::StaticGetValidKeyLength(keyLength);
    case Camellia:
        return CryptoPP::Camellia_Info::StaticGetValidKeyLength(keyLength);
    case DES_EDE3:
        return CryptoPP::DES_EDE3_Info::StaticGetValidKeyLength(keyLength);
    case IDEA:
        return CryptoPP::IDEA_Info::StaticGetValidKeyLength(keyLength);
    case SEED:
        return CryptoPP::SEED_Info::StaticGetValidKeyLength(keyLength);
    case Serpent:
        return CryptoPP::Serpent_Info::StaticGetValidKeyLength(keyLength);
    case Twofish:
        return CryptoPP::Twofish_Info::StaticGetValidKeyLength(keyLength);
    default:
        return 0;
    }
}
