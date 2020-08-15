#ifndef WORKER_H
#define WORKER_H

#include <QString>

enum class Browser
{
    GoogleChrome,
    Yandex
};

class Worker
{
    QString chrome_path_;
    QString chrome_key_path_;
    QString yandex_path_;

    QString out_file_name_;

public:
    Worker();
    ~Worker();

    void run();
    QString chooseBrowser(const QMap<Browser, QString> &installed_browsers_map);

    void handleGoogleChrome();
    void handleYandex();

    bool decryptDPAPI(const QByteArray &encrypted_data, QByteArray &decrypted_data);
    bool decryptAES_256_GSM(const QByteArray &encrypted_data,
                    const QByteArray &key,
                    const QByteArray &initialization_vector,
                    const QByteArray &authentication_tag,
                    QByteArray &decrypted_data);
};

#endif // WORKER_H
