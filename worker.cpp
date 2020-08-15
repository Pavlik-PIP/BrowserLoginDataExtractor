#include "worker.h"

#include <QtSql>

#include <windows.h> //For DATA_BLOB and BYTE types
#include <openssl/evp.h>

#include "GlobalDefinitions/console.h"

Worker::Worker()
{
    QString standard_path_part = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation);

    chrome_path_ = standard_path_part + "\\Google\\Chrome\\User Data\\Default\\Login Data";
    chrome_key_path_ = standard_path_part + "\\Google\\Chrome\\User Data\\Local State";
    yandex_path_ = standard_path_part + "\\Yandex\\YandexBrowser\\User Data\\Default\\Ya Login Data";
}

QString Worker::chooseBrowser(const QMap<Browser, QString> &installed_browsers_map)
{
    console::qStdOut() << "Choose browser to extract from:" << endl;

    QStringList values = installed_browsers_map.values();
    for(int i = 0; i < values.size(); i++)
        console::qStdOut() << "    " << QString::number(i + 1) + " - " + values.at(i) << endl;

    QString answer = console::qStdIn().readLine().trimmed();
    if(answer.isEmpty())
    {
        console::qStdErr() << "Error: empty parameter passed" << endl;
        return nullptr;
    }
    bool ok;
    int browser_index = answer.toInt(&ok);
    if(!ok || browser_index <= 0 || browser_index > values.size())
    {
        console::qStdErr() << "Error: invalid parameter passed: " << answer << endl;
        return nullptr;
    }

    if(answer.isEmpty())
        browser_index = 0;
    else
        browser_index = --browser_index;

    return values.at(browser_index);
}

void Worker::run()
{
    console::qStdOut() << "Command line app for extracting browser's login data to *.csv file" << endl << endl;

    QMap<Browser, QString> installed_browsers_map;
    QFileInfo fileInfo;

    fileInfo.setFile(chrome_path_);
    if(fileInfo.exists())
        installed_browsers_map.insert(Browser::GoogleChrome, "Google Chrome");
    fileInfo.setFile(yandex_path_);
    if(fileInfo.exists())
        installed_browsers_map.insert(Browser::Yandex, "Yandex browser");

    if(!installed_browsers_map.isEmpty())
    {
        QString browserName = chooseBrowser(installed_browsers_map);
        if(browserName.isNull())
            return;
        out_file_name_ = browserName + " passwords.csv";

        Browser browser = installed_browsers_map.key(browserName);

        switch(browser)
        {
            case Browser::GoogleChrome:
                handleGoogleChrome();
                break;
            case Browser::Yandex:
                handleYandex();
                break;
        }
    }
    else
        console::qStdErr() << "Error: Couldn't find any browsers on your computer" << endl;
}

void Worker::handleGoogleChrome()
{
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "MainDB");
    db.setDatabaseName(chrome_path_);

    if(!db.open())
    {
        console::qStdErr() << "Error: " << db.lastError().text() << endl;
        return;
    }

    QFile json_file(chrome_key_path_);

    json_file.open(QFile::ReadOnly);
    QJsonDocument json_document = QJsonDocument::fromJson(json_file.readAll());
    json_file.close();

    QJsonObject json_object = json_document.object();
    QJsonObject os_crypt_object = json_object.value("os_crypt").toObject();

    QByteArray encrypted_key = os_crypt_object.value("encrypted_key").toString().toUtf8();
    encrypted_key = QByteArray::fromBase64(encrypted_key);

    // Key prefix for a key encrypted with DPAPI.
    const QString DPAPI_key_prefix = "DPAPI";

    encrypted_key = encrypted_key.remove(0, DPAPI_key_prefix.size());

    QByteArray decrypted_key;
    if(!decryptDPAPI(encrypted_key, decrypted_key))
    {
        console::qStdErr() << "Error: Couldn't decrypt key" << endl;
        return;
    }

    QSqlQuery query(db);
    query.exec("SELECT origin_url, username_value, password_value, date_last_used FROM logins");
    if(!query.isActive())
    {
        console::qStdErr() << "Error: " << query.lastError().text() << endl;
        console::qStdOut() << "Make sure Google Chrome is not running and try again" << endl;
        return;
    }

    QFile file(out_file_name_);
    QTextStream fout(&file);

    file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text);
    fout << "name,url,username,password" << endl;

    // Version prefix for data encrypted with profile bound key.
    const QString encryption_version_prefix = "v10";

    const int iv_length = 96 / 8; // 12

    const int auth_tag_length = 128 / 8; // 16

    while (query.next())
    {
        QByteArray encrypted_password = query.value(2).toByteArray();

        encrypted_password = encrypted_password.remove(0, encryption_version_prefix.size());
        int encrypted_password_length = encrypted_password.size() - (iv_length + auth_tag_length);
        QByteArray iv = encrypted_password.left(iv_length);
        QByteArray auth_tag = encrypted_password.right(auth_tag_length);
        encrypted_password = encrypted_password.mid(iv_length, encrypted_password_length);

        QString line;
        line.append(',');
        line.append(query.value(0).toString() + ',');
        line.append(query.value(1).toString() + ',');

        QByteArray decrypted_password;
        if(decryptAES_256_GSM(encrypted_password, decrypted_key, iv, auth_tag, decrypted_password))
            line.append(decrypted_password);
        else
            line.append("DECRYPTION_FAILED");

        fout << line << endl;
    }
    file.close();

    db.close();

    console::qStdOut() << "File \"" << out_file_name_ << "\" has been successfully created" << endl;
}

void Worker::handleYandex()
{}

bool Worker::decryptDPAPI(const QByteArray &encrypted_data, QByteArray &decrypted_data)
{
    DATA_BLOB data_in;
    DATA_BLOB data_out;

    data_in.pbData = const_cast<BYTE*>(reinterpret_cast<const BYTE*>(encrypted_data.data()));
    data_in.cbData = static_cast<DWORD>(encrypted_data.size());

    if(CryptUnprotectData(&data_in, nullptr, nullptr, nullptr, nullptr, 0, &data_out))
    {
        decrypted_data = QByteArray::fromRawData(reinterpret_cast<const char*>(data_out.pbData), static_cast<int>(data_out.cbData));
        return true;
    }
    else
        return false;
}

bool Worker::decryptAES_256_GSM(const QByteArray &encrypted_data,
                const QByteArray &key,
                const QByteArray &initialization_vector,
                const QByteArray &authentication_tag,
                QByteArray &decrypted_data)
{
    unsigned char *ciphertext_data = reinterpret_cast<unsigned char*>(const_cast<char*>(encrypted_data.data()));
    int ciphertext_len = encrypted_data.size();

    unsigned char *key_data = reinterpret_cast<unsigned char*>(const_cast<char*>(key.data()));

    unsigned char *iv_data = reinterpret_cast<unsigned char*>(const_cast<char*>(initialization_vector.data()));
    int iv_len = initialization_vector.size();

    unsigned char *tag_data = reinterpret_cast<unsigned char*>(const_cast<char*>(authentication_tag.data()));
    int tag_len = authentication_tag.size();

    int buffer_size = ciphertext_len + 256; // ciphertext_len + cipher_block_size
    unsigned char output_text[buffer_size];
    int output_text_len;
    int ret;

    EVP_CIPHER_CTX *ctx;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(iv_len != 12)
    {
        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr))
        {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_data, iv_data))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, output_text, &output_text_len, ciphertext_data, ciphertext_len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    decrypted_data = QByteArray::fromRawData(reinterpret_cast<const char*>(output_text), output_text_len);

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag_data))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, output_text + output_text_len, &output_text_len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret < 0)
        return false;

    return true;
}

Worker::~Worker()
{
    QSqlDatabase::removeDatabase("MainDB");
}
