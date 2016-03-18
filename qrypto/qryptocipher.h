#ifndef QRYPTOPP_CIPHER_H
#define QRYPTOPP_CIPHER_H

#include <QObject>

namespace QryptoPP
{

class Cipher : public QObject
{
    Q_OBJECT

public:
    enum Algorithm {
        AES,
        Blowfish,
        Camellia,
        IDEA,
        SEED,
        Serpent,
        Twofish,
        UnknownAlgorithm
    };

    enum Operation {
        CBC,
        CFB,
        CTR,
        ECB,
        OFB,
        UnknownOperation
    };

    Q_ENUM(Algorithm)
    Q_ENUM(Operation)
    Q_PROPERTY(Algorithm algorithm MEMBER m_algorithm)
    Q_PROPERTY(Operation operation MEMBER m_operation)
    Q_PROPERTY(QByteArray initialisationVector MEMBER m_IV)
    Q_PROPERTY(QByteArray salt MEMBER m_salt)
    Q_PROPERTY(uint iterationCount MEMBER m_iteration)
    Q_PROPERTY(uint keyLength MEMBER m_keyLength)

    explicit Cipher(QObject *parent = 0) :
        QObject(parent),
        m_salt(16, 0),
        m_iteration(100000),
        m_keyLength(16),
        m_IV(16, 0),
        m_algorithm(AES),
        m_operation(CTR)
    { }

    ~Cipher() { }

    bool canDecrypt() const;

    bool canEncrypt() const;

    bool decrypt(QByteArray &dst, const QByteArray &password, const QByteArray &src);

    bool encrypt(QByteArray &dst, const QByteArray &password, const QByteArray &src);

protected:

    QByteArray m_salt;
    uint m_iteration;
    uint m_keyLength;
    QByteArray m_IV;
    Algorithm m_algorithm;
    Operation m_operation;

    template <typename Alg>
    struct Action;

    template <typename Alg>
    friend struct Action;
};

}

#endif // QRYPTOPP_CIPHER_H
