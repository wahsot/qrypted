#ifndef QRYPTICSTREAM_H
#define QRYPTICSTREAM_H

#include <QObject>

class QIODevice;

class QrypticStream : public QObject
{
    Q_OBJECT
    struct Private;
    Private *d;

public:
    enum Cipher {
        IDEA,
        Blowfish,
        Camellia,
        Rijndael,
        Serpent,
        Twofish,
        UnknownCipher
    };

    static const QStringList Ciphers;

    enum Digest {
        Sha1,
        Sha256,
        Sha512,
        Sha3_256,
        Sha3_512,
        UnknownDigest
    };

    static const QStringList Digests;

    enum KeyDerivation {
        PKCS5_PBKDF1,
        PKCS5_PBKDF2_HMAC,
        //PKCS12_PBKDF,
        UnknownKeyDerivation,
    };

    enum Method {
        ElectronicCodebook,
        CipherBlockChaining,
        CipherFeedback,
        OutputFeedback,
        Counter,
        UnknownMethod
    };

    static const QStringList Methods;

    struct Settings
    {
        KeyDerivation keyDerivation;
        Digest digest;
        unsigned iterations;
        unsigned saltLength;
        Method method;
        Cipher cipher;

        Settings(Cipher c = Rijndael, Method m = CipherBlockChaining, Digest d = Sha256,
                 KeyDerivation k = PKCS5_PBKDF2_HMAC, int iterations = 99999) :
            keyDerivation(k),
            digest(d),
            iterations(iterations),
            saltLength(16),
            method(m),
            cipher(c)
        { }
    };

    explicit QrypticStream(QIODevice *device = 0);

    ~QrypticStream();

    bool decrypt(QByteArray &dst);

    QIODevice *device() const;

    bool encrypt(const QByteArray &src);

    void setDevice(QIODevice *device);

    void setPassword(const QString &plain);

    void setSettings(const Settings &settings);

    const Settings &settings() const;

signals:
    void passwordRequired();

public slots:

};

#endif // QRYPTICSTREAM_H
