/****************************************************************************
**
** Copyright (C) 2016 The Qt Company Ltd.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the QtNetwork module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 3 as published by the Free Software
** Foundation and appearing in the file LICENSE.LGPL3 included in the
** packaging of this file. Please review the following information to
** ensure the GNU Lesser General Public License version 3 requirements
** will be met: https://www.gnu.org/licenses/lgpl-3.0.html.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 2.0 or (at your option) the GNU General
** Public license version 3 or any later version approved by the KDE Free
** Qt Foundation. The licenses are as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL2 and LICENSE.GPL3
** included in the packaging of this file. Please review the following
** information to ensure the GNU General Public License requirements will
** be met: https://www.gnu.org/licenses/gpl-2.0.html and
** https://www.gnu.org/licenses/gpl-3.0.html.
**
** $QT_END_LICENSE$
**
****************************************************************************/

#include "qsslcertificate.h"
#include "qsslcertificate_p.h"

#include "qssl_p.h"
#ifndef QT_NO_SSL
#include "qsslkey.h"
#include "qsslkey_p.h"
#endif
#include "qsslcertificateextension.h"
#include "qsslcertificateextension_p.h"
#include "qasn1element_p.h"

#include <QtCore/qdatastream.h>
#include <QtCore/qendian.h>
#include <QtNetwork/qhostaddress.h>

#ifdef Q_OS_MACOS
#include <QtCore/private/qcore_mac_p.h>
#include <CoreServices/CoreServices.h>
#include <QTimeZone>
#endif

QT_BEGIN_NAMESPACE

bool QSslCertificate::operator==(const QSslCertificate &other) const
{
    if (d == other.d)
        return true;
    if (d->null && other.d->null)
        return true;
    return d->derData == other.d->derData;
}

uint qHash(const QSslCertificate &key, uint seed) noexcept
{
    // DER is the native encoding here, so toDer() is just "return d->derData":
    return qHash(key.toDer(), seed);
}

bool QSslCertificate::isNull() const
{
    return d->null;
}

bool QSslCertificate::isSelfSigned() const
{
    if (d->null)
        return false;

    qCWarning(lcSsl,
              "QSslCertificate::isSelfSigned: This function does not check, whether the certificate "
              "is actually signed. It just checks whether issuer and subject are identical");
    return d->subjectMatchesIssuer;
}

QByteArray QSslCertificate::version() const
{
    return d->versionString;
}

QByteArray QSslCertificate::serialNumber() const
{
    return d->serialNumberString;
}

QStringList QSslCertificate::issuerInfo(SubjectInfo info) const
{
    return issuerInfo(QSslCertificatePrivate::subjectInfoToString(info));
}

QStringList QSslCertificate::issuerInfo(const QByteArray &attribute) const
{
    return d->issuerInfo.values(attribute);
}

QStringList QSslCertificate::subjectInfo(SubjectInfo info) const
{
    return subjectInfo(QSslCertificatePrivate::subjectInfoToString(info));
}

QStringList QSslCertificate::subjectInfo(const QByteArray &attribute) const
{
    return d->subjectInfo.values(attribute);
}

QList<QByteArray> QSslCertificate::subjectInfoAttributes() const
{
    return d->subjectInfo.uniqueKeys();
}

QList<QByteArray> QSslCertificate::issuerInfoAttributes() const
{
    return d->issuerInfo.uniqueKeys();
}

QMultiMap<QSsl::AlternativeNameEntryType, QString> QSslCertificate::subjectAlternativeNames() const
{
    return d->subjectAlternativeNames;
}

QDateTime QSslCertificate::effectiveDate() const
{
    return d->notValidBefore;
}

QDateTime QSslCertificate::expiryDate() const
{
    return d->notValidAfter;
}

#if !defined(Q_OS_WINRT) && !QT_CONFIG(schannel) // implemented in qsslcertificate_{winrt,schannel}.cpp
Qt::HANDLE QSslCertificate::handle() const
{
    Q_UNIMPLEMENTED();
    return nullptr;
}
#endif

#ifndef QT_NO_SSL
QSslKey QSslCertificate::publicKey() const
{
    QSslKey key;
    key.d->type = QSsl::PublicKey;
    if (d->publicKeyAlgorithm != QSsl::Opaque) {
    key.d->algorithm = d->publicKeyAlgorithm;
    key.d->decodeDer(d->publicKeyDerData);
    }
    return key;
}
#endif

QList<QSslCertificateExtension> QSslCertificate::extensions() const
{
    return d->extensions;
}

#define BEGINCERTSTRING "-----BEGIN CERTIFICATE-----"
#define ENDCERTSTRING "-----END CERTIFICATE-----"

QByteArray QSslCertificate::toPem() const
{
    QByteArray array = toDer();

    // Convert to Base64 - wrap at 64 characters.
    array = array.toBase64();
    QByteArray tmp;
    for (int i = 0; i <= array.size() - 64; i += 64) {
        tmp += QByteArray::fromRawData(array.data() + i, 64);
        tmp += '\n';
    }
    if (int remainder = array.size() % 64) {
        tmp += QByteArray::fromRawData(array.data() + array.size() - remainder, remainder);
        tmp += '\n';
    }

    return BEGINCERTSTRING "\n" + tmp + ENDCERTSTRING "\n";
}

QByteArray QSslCertificate::toDer() const
{
    return d->derData;
}

#ifdef Q_OS_MACOS
static CFStringRef stringFromArray(CFArrayRef array, CFStringRef key)
{
    if(!array)
        return nullptr;

    QString out;
    for (CFIndex n = 0 ; n < CFArrayGetCount(array); n++) {
        CFDictionaryRef dict = (CFDictionaryRef)CFArrayGetValueAtIndex(array, n);
        if (CFGetTypeID(dict) != CFDictionaryGetTypeID())
            continue;
        CFTypeRef dictkey = CFDictionaryGetValue(dict, kSecPropertyKeyLabel);
        if (!CFEqual(dictkey, key))
            continue;
        CFStringRef str = (CFStringRef) CFDictionaryGetValue(dict, kSecPropertyKeyValue);
        return str;
    }

    return nullptr;
}

static QString stringFromArrayWithKeys(CFArrayRef array, QList<CFStringRef> keys, QStringList labels)
{
    if(!array)
        return {};

    QStringList out;
    for(int i = 0; i < keys.size();  i++) {
        CFStringRef str = stringFromArray(array, keys[i]);
        out << QString(QLatin1Literal("%1=%2")).arg(labels[i], QString::fromCFString(str));
    }
    return out.join(QLatin1Literal(", "));
}

static QString extractDateTime(CFDictionaryRef vals, CFTypeRef dateTimeRef)
{
    CFNumberRef validityNotBeforeRef = (CFNumberRef)CFDictionaryGetValue((CFDictionaryRef)CFDictionaryGetValue(vals, dateTimeRef), kSecPropertyKeyValue);
    CFAbsoluteTime validityNotBefore;
    CFNumberGetValue(validityNotBeforeRef, kCFNumberDoubleType, &validityNotBefore);

    static CFTimeZoneRef zoneSystem = CFTimeZoneCopySystem();
    CFGregorianDate validityNotBeforeGregorianDate = CFAbsoluteTimeGetGregorianDate(validityNotBefore, zoneSystem);

    QDate qd(validityNotBeforeGregorianDate.year, validityNotBeforeGregorianDate.month, validityNotBeforeGregorianDate.day);

    QString buffer = QString(QLatin1Literal("%1 %2 %3:%4:%5 %6 GMT"))
            .arg(qd.toString(QLatin1Literal("MMM")))
            .arg(QString::number(qd.day()), 2, QLatin1Char(' '))
            .arg(validityNotBeforeGregorianDate.hour, 2, 10, QLatin1Char('0'))
            .arg(validityNotBeforeGregorianDate.minute, 2, 10, QLatin1Char('0'))
            .arg((int) validityNotBeforeGregorianDate.second, 2, 10, QLatin1Char('0'))
            .arg(qd.year());
    return buffer;
}

static QString stringFromCertificate(SecCertificateRef certificateRef)
{
   if (certificateRef == NULL)
       return {};

    QMap<QString, QString> algorithMap({
                    {QLatin1Literal("1.2.840.10040.4.3"), QLatin1Literal("sha1DSA")},
                    {QLatin1Literal("1.2.840.10045.4.1"), QLatin1Literal("ecdsa-with-SHA1")},
                    {QLatin1Literal("1.2.840.10045.4.2"), QLatin1Literal("ecdsa-with-Recommended")},
                    {QLatin1Literal("1.2.840.10045.4.3.2"), QLatin1Literal("ecdsa-with-SHA256")},
                    {QLatin1Literal("1.2.840.10045.4.3.3"), QLatin1Literal("ecdsa-with-SHA384")},
                    {QLatin1Literal("1.2.840.10045.4.3.4"), QLatin1Literal("ecdsa-with-SHA512")},
                    {QLatin1Literal("1.2.840.10045.4.3"), QLatin1Literal("ecdsa-with-SHA2")},
                    {QLatin1Literal("1.2.840.113549.1.1.10"), QLatin1Literal("rsassa-pss")},
                    {QLatin1Literal("1.2.840.113549.1.1.11"), QLatin1Literal("sha256WithRSAEncryption")},
                    {QLatin1Literal("1.2.840.113549.1.1.12"), QLatin1Literal("sha384WithRSAEncryption")},
                    {QLatin1Literal("1.2.840.113549.1.1.13"), QLatin1Literal("sha512WithRSAEncryption")},
                    {QLatin1Literal("1.2.840.113549.1.1.2"), QLatin1Literal("md2WithRSAEncryption")},
                    {QLatin1Literal("1.2.840.113549.1.1.3"), QLatin1Literal("md4withRSAEncryption")},
                    {QLatin1Literal("1.2.840.113549.1.1.4"), QLatin1Literal("md5WithRSAEncryption")},
                    {QLatin1Literal("1.2.840.113549.1.1.5"), QLatin1Literal("sha1-with-rsa-signature")},
                    {QLatin1Literal("1.2.840.113549.2.5"), QLatin1Literal("md5")},
                    {QLatin1Literal("1.3.14.3.2.13"), QLatin1Literal("dsaWithSHA")},
                    {QLatin1Literal("1.3.14.3.2.15"), QLatin1Literal("shaWithRSASignature")},
                    {QLatin1Literal("1.3.14.3.2.2"), QLatin1Literal("md4WithRSA")},
                    {QLatin1Literal("1.3.14.3.2.26"), QLatin1Literal("hashAlgorithmIdentifier")},
                    {QLatin1Literal("1.3.14.3.2.27"), QLatin1Literal("dsaWithSHA1")},
                    {QLatin1Literal("1.3.14.3.2.29"), QLatin1Literal("sha-1WithRSAEncryption")},
                    {QLatin1Literal("1.3.14.3.2.3"), QLatin1Literal("md5WithRSA")},
                    {QLatin1Literal("1.3.14.3.2.4"), QLatin1Literal("md4WithRSAEncryption")},
                    {QLatin1Literal("1.3.14.7.2.3.1"), QLatin1Literal("md2WithRsa")},
                    {QLatin1Literal("2.16.840.1.101.2.1.1.19"), QLatin1Literal("mosaicUpdatedSig")},
                    {QLatin1Literal("2.16.840.1.101.3.4.2.1"), QLatin1Literal("sha256NoSign")},
                    {QLatin1Literal("2.16.840.1.101.3.4.2.2"), QLatin1Literal("sha384NoSign")},
                    {QLatin1Literal("2.16.840.1.101.3.4.2.3"), QLatin1Literal("sha512NoSign")},
    });
    QMap<QString, QString> publicKeyMap({
                    {QLatin1Literal("1.2.840.10040.4.1"), QLatin1Literal("dsa")},
                    {QLatin1Literal("1.2.840.10045.2.1"), QLatin1Literal("id-ecPublicKey")},
                    {QLatin1Literal("1.2.840.10045.3.1.7"), QLatin1Literal("prime256v1")},
                    {QLatin1Literal("1.2.840.10046.2.1"), QLatin1Literal("dhpublicnumber")},
                    {QLatin1Literal("1.2.840.113549.1.1.1"), QLatin1Literal("rsaEncryption")},
                    {QLatin1Literal("1.2.840.113549.1.1.10"), QLatin1Literal("rsaEncryption")},
                    {QLatin1Literal("1.2.840.113549.1.1.7"), QLatin1Literal("id-RSAES-OAEP")},
                    {QLatin1Literal("1.2.840.113549.1.3.1"), QLatin1Literal("dhKeyAgreement")},
                    {QLatin1Literal("1.2.840.113549.1.9.16.3.5"), QLatin1Literal("alg-ESDH")},
                    {QLatin1Literal("1.3.132.0.34"), QLatin1Literal("ansip384r1")},
                    {QLatin1Literal("1.3.132.0.35"), QLatin1Literal("ansip521r1")},
                    {QLatin1Literal("1.3.133.16.840.63.0.2"), QLatin1Literal("dhSinglePass-stdDH-sha1kdf-scheme")},
                    {QLatin1Literal("1.3.14.3.2.12"), QLatin1Literal("dsa")},
                    {QLatin1Literal("1.3.14.3.2.22"), QLatin1Literal("rsa-key-transportpong ")},
                    {QLatin1Literal("1.3.6.1.5.5.7.6.2"), QLatin1Literal("noSignature")},
                    {QLatin1Literal("2.16.840.1.101.2.1.1.20"), QLatin1Literal("mosaicKMandUpdSig")},
    });

    CFStringRef commonNameRef;
    OSStatus status;
    if ((status = SecCertificateCopyCommonName(certificateRef, &commonNameRef)) != errSecSuccess) {
//        NSLog(@"Could not extract name from cert: %@",
//              SecCopyErrorMessageString(status, NULL));
        return QLatin1Literal("Unreadable cert");
    };

    CFErrorRef error;

    QList<CFStringRef> idKeys = { kSecOIDCountryName, kSecOIDStateProvinceName, kSecOIDLocalityName,
                                  kSecOIDOrganizationName, kSecOIDOrganizationalUnitName, kSecOIDCommonName };
    QStringList idLabels = { QLatin1Literal("C"), QLatin1Literal("ST"), QLatin1Literal("L"),
                             QLatin1Literal("O"), QLatin1Literal("OU"), QLatin1Literal("CN") };

    QVector<CFStringRef> keys = { kSecOIDX509V1SubjectName, kSecOIDX509V1IssuerName,
                                  kSecOIDX509V1SerialNumber, kSecOIDX509V1Signature, kSecOIDX509V1Version,
                                  kSecOIDX509V1ValidityNotAfter, kSecOIDX509V1ValidityNotBefore,
                                  kSecOIDX509V1Version, kSecOIDX509V1SubjectPublicKey,
                                  kSecOIDX509V1SubjectPublicKeyAlgorithm,
                                  kSecOIDX509V1SignatureAlgorithm };
    CFArrayRef keySelection = CFArrayCreate(NULL, (const void**)keys.constData(), keys.size(), &kCFTypeArrayCallBacks);

    CFDictionaryRef vals = SecCertificateCopyValues(certificateRef, keySelection, &error);

    int version = CFStringGetIntValue((CFStringRef) CFDictionaryGetValue((CFDictionaryRef) CFDictionaryGetValue(vals, kSecOIDX509V1Version), kSecPropertyKeyValue));
    QString versionString = version == 3 ? QLatin1Literal("0x2") : QLatin1Literal("0x0");   // hard coded, don't know how to read
    QString validityNotBefore = extractDateTime(vals, kSecOIDX509V1ValidityNotBefore);
    QString validityNotAfter = extractDateTime(vals, kSecOIDX509V1ValidityNotAfter);
    QString serialNumber = QString::fromCFString((CFStringRef)CFDictionaryGetValue((CFDictionaryRef)CFDictionaryGetValue(vals, kSecOIDX509V1SerialNumber), kSecPropertyKeyValue));
    serialNumber = serialNumber.toLower().replace(QLatin1Char(' '), QLatin1Char(':'));

    QString signatureAlgorithm;
    {
        CFDictionaryRef dict = (CFDictionaryRef)CFDictionaryGetValue(vals, kSecOIDX509V1SignatureAlgorithm);
        CFArrayRef values = (CFArrayRef) CFDictionaryGetValue(dict, kSecPropertyKeyValue);
        signatureAlgorithm = QString::fromCFString(stringFromArray(values, QString(QLatin1Literal("Algorithm")).toCFString()));
        if (algorithMap.contains(signatureAlgorithm))
            signatureAlgorithm = algorithMap[signatureAlgorithm];
    }

    QString subjectDetails;
    {
        CFDictionaryRef dict = (CFDictionaryRef)CFDictionaryGetValue(vals, kSecOIDX509V1SubjectName);
        CFArrayRef values = (CFArrayRef) CFDictionaryGetValue(dict, kSecPropertyKeyValue);
        subjectDetails += stringFromArrayWithKeys(values, idKeys, idLabels);
    }

    QString pkAlgorithm;
    {
        CFDictionaryRef dict = (CFDictionaryRef)CFDictionaryGetValue(vals, kSecOIDX509V1SubjectPublicKeyAlgorithm);
        CFArrayRef values = (CFArrayRef) CFDictionaryGetValue(dict, kSecPropertyKeyValue);
        pkAlgorithm = QString::fromCFString(stringFromArray(values, QString(QLatin1Literal("Algorithm")).toCFString()));
        if (publicKeyMap.contains(pkAlgorithm))
            pkAlgorithm = publicKeyMap[pkAlgorithm];
    }

    QString issuerDetails;
    {
        CFDictionaryRef dict = (CFDictionaryRef)CFDictionaryGetValue(vals, kSecOIDX509V1IssuerName);
        CFArrayRef values = (CFArrayRef) CFDictionaryGetValue(dict, kSecPropertyKeyValue);
        issuerDetails += stringFromArrayWithKeys(values, idKeys, idLabels);
    }

    QLatin1Literal format = QLatin1Literal(R"*(
Certificate:
    Data:
        Version: %1 (%2)
        Serial Number:
            %3
    Signature Algorithm: %4
        Issuer: %5
        Validity
            Not Before: %6
            Not After : %7
        Subject: %8
        Subject Public Key Info:
            Public Key Algorithm: %9
)*");
    QString longDesc = QString(format).arg(QString::number(version), versionString,
                                           serialNumber,
                                           signatureAlgorithm,
                                           issuerDetails,
                                           validityNotBefore,
                                           validityNotAfter,
                                           subjectDetails,
                                           pkAlgorithm);

    CFRelease(vals);
    CFRelease(commonNameRef);
    CFRelease(keySelection);

    return longDesc;
}
#endif

QString QSslCertificate::toText() const
{
#ifdef Q_OS_MACOS
    QCFType<CFDataRef> certData = d->derData.toCFData();
    QCFType<SecCertificateRef> certRef = SecCertificateCreateWithData(NULL, certData);

    return stringFromCertificate(certRef);
#else
    Q_UNIMPLEMENTED();
    return QString();
#endif
}

void QSslCertificatePrivate::init(const QByteArray &data, QSsl::EncodingFormat format)
{
    if (!data.isEmpty()) {
        const QList<QSslCertificate> certs = (format == QSsl::Pem)
            ? certificatesFromPem(data, 1)
            : certificatesFromDer(data, 1);
        if (!certs.isEmpty()) {
            *this = *certs.first().d;
#if QT_CONFIG(schannel)
            if (certificateContext)
                certificateContext = CertDuplicateCertificateContext(certificateContext);
#endif
        }
    }
}

static bool matchLineFeed(const QByteArray &pem, int *offset)
{
    char ch = 0;

    // ignore extra whitespace at the end of the line
    while (*offset < pem.size() && (ch = pem.at(*offset)) == ' ')
        ++*offset;

    if (ch == '\n') {
        *offset += 1;
        return true;
    }
    if (ch == '\r' && pem.size() > (*offset + 1) && pem.at(*offset + 1) == '\n') {
        *offset += 2;
        return true;
    }
    return false;
}

QList<QSslCertificate> QSslCertificatePrivate::certificatesFromPem(const QByteArray &pem, int count)
{
    QList<QSslCertificate> certificates;
    int offset = 0;
    while (count == -1 || certificates.size() < count) {
        int startPos = pem.indexOf(BEGINCERTSTRING, offset);
        if (startPos == -1)
            break;
        startPos += sizeof(BEGINCERTSTRING) - 1;
        if (!matchLineFeed(pem, &startPos))
            break;

        int endPos = pem.indexOf(ENDCERTSTRING, startPos);
        if (endPos == -1)
            break;

        offset = endPos + sizeof(ENDCERTSTRING) - 1;
        if (offset < pem.size() && !matchLineFeed(pem, &offset))
            break;

        QByteArray decoded = QByteArray::fromBase64(
            QByteArray::fromRawData(pem.data() + startPos, endPos - startPos));
        certificates << certificatesFromDer(decoded, 1);;
    }

    return certificates;
}

QList<QSslCertificate> QSslCertificatePrivate::certificatesFromDer(const QByteArray &der, int count)
{
    QList<QSslCertificate> certificates;

    QByteArray data = der;
    while (count == -1 || certificates.size() < count) {
        QSslCertificate cert;
        if (!cert.d->parse(data))
            break;

        certificates << cert;
        data.remove(0, cert.d->derData.size());
    }

    return certificates;
}

static QByteArray colonSeparatedHex(const QByteArray &value)
{
    const int size = value.size();
    int i = 0;
    while (i < size && !value.at(i)) // skip leading zeros
       ++i;

    return value.mid(i).toHex(':');
}

bool QSslCertificatePrivate::parse(const QByteArray &data)
{
    QAsn1Element root;

    QDataStream dataStream(data);
    if (!root.read(dataStream) || root.type() != QAsn1Element::SequenceType)
        return false;

    QDataStream rootStream(root.value());
    QAsn1Element cert;
    if (!cert.read(rootStream) || cert.type() != QAsn1Element::SequenceType)
        return false;

    // version or serial number
    QAsn1Element elem;
    QDataStream certStream(cert.value());
    if (!elem.read(certStream))
        return false;

    if (elem.type() == QAsn1Element::Context0Type) {
        QDataStream versionStream(elem.value());
        if (!elem.read(versionStream) || elem.type() != QAsn1Element::IntegerType)
            return false;

        versionString = QByteArray::number(elem.value().at(0) + 1);
        if (!elem.read(certStream))
            return false;
    } else {
        versionString = QByteArray::number(1);
    }

    // serial number
    if (elem.type() != QAsn1Element::IntegerType)
        return false;
    serialNumberString = colonSeparatedHex(elem.value());

    // algorithm ID
    if (!elem.read(certStream) || elem.type() != QAsn1Element::SequenceType)
        return false;

    // issuer info
    if (!elem.read(certStream) || elem.type() != QAsn1Element::SequenceType)
        return false;

    QByteArray issuerDer = data.mid(dataStream.device()->pos() - elem.value().length(), elem.value().length());
    issuerInfo = elem.toInfo();

    // validity period
    if (!elem.read(certStream) || elem.type() != QAsn1Element::SequenceType)
        return false;

    QDataStream validityStream(elem.value());
    if (!elem.read(validityStream) || (elem.type() != QAsn1Element::UtcTimeType && elem.type() != QAsn1Element::GeneralizedTimeType))
        return false;

    notValidBefore = elem.toDateTime();
    if (!elem.read(validityStream) || (elem.type() != QAsn1Element::UtcTimeType && elem.type() != QAsn1Element::GeneralizedTimeType))
        return false;

    notValidAfter = elem.toDateTime();

    // subject name
    if (!elem.read(certStream) || elem.type() != QAsn1Element::SequenceType)
        return false;

    QByteArray subjectDer = data.mid(dataStream.device()->pos() - elem.value().length(), elem.value().length());
    subjectInfo = elem.toInfo();
    subjectMatchesIssuer = issuerDer == subjectDer;

    // public key
    qint64 keyStart = certStream.device()->pos();
    if (!elem.read(certStream) || elem.type() != QAsn1Element::SequenceType)
        return false;

    publicKeyDerData.resize(certStream.device()->pos() - keyStart);
    QDataStream keyStream(elem.value());
    if (!elem.read(keyStream) || elem.type() != QAsn1Element::SequenceType)
        return false;


    // key algorithm
    if (!elem.read(elem.value()) || elem.type() != QAsn1Element::ObjectIdentifierType)
        return false;

    const QByteArray oid = elem.toObjectId();
    if (oid == RSA_ENCRYPTION_OID)
        publicKeyAlgorithm = QSsl::Rsa;
    else if (oid == DSA_ENCRYPTION_OID)
        publicKeyAlgorithm = QSsl::Dsa;
    else if (oid == EC_ENCRYPTION_OID)
        publicKeyAlgorithm = QSsl::Ec;
    else
        publicKeyAlgorithm = QSsl::Opaque;

    certStream.device()->seek(keyStart);
    certStream.readRawData(publicKeyDerData.data(), publicKeyDerData.size());

    // extensions
    while (elem.read(certStream)) {
        if (elem.type() == QAsn1Element::Context3Type) {
            if (elem.read(elem.value()) && elem.type() == QAsn1Element::SequenceType) {
                QDataStream extStream(elem.value());
                while (elem.read(extStream) && elem.type() == QAsn1Element::SequenceType) {
                    QSslCertificateExtension extension;
                    if (!parseExtension(elem.value(), &extension))
                        return false;
                    extensions << extension;

                    if (extension.oid() == QLatin1String("2.5.29.17")) {
                        // subjectAltName
                        QAsn1Element sanElem;
                        if (sanElem.read(extension.value().toByteArray()) && sanElem.type() == QAsn1Element::SequenceType) {
                            QDataStream nameStream(sanElem.value());
                            QAsn1Element nameElem;
                            while (nameElem.read(nameStream)) {
                                switch (nameElem.type()) {
                                case QAsn1Element::Rfc822NameType:
                                    subjectAlternativeNames.insert(QSsl::EmailEntry, nameElem.toString());
                                    break;
                                case QAsn1Element::DnsNameType:
                                    subjectAlternativeNames.insert(QSsl::DnsEntry, nameElem.toString());
                                    break;
                                case QAsn1Element::IpAddressType: {
                                    QHostAddress ipAddress;
                                    QByteArray ipAddrValue = nameElem.value();
                                    switch (ipAddrValue.length()) {
                                    case 4: // IPv4
                                        ipAddress = QHostAddress(qFromBigEndian(*reinterpret_cast<quint32 *>(ipAddrValue.data())));
                                        break;
                                    case 16: // IPv6
                                        ipAddress = QHostAddress(reinterpret_cast<quint8 *>(ipAddrValue.data()));
                                        break;
                                    default: // Unknown IP address format
                                        break;
                                    }
                                    if (!ipAddress.isNull())
                                        subjectAlternativeNames.insert(QSsl::IpAddressEntry, ipAddress.toString());
                                    break;
                                }
                                default:
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    derData = data.left(dataStream.device()->pos());
    null = false;
    return true;
}

bool QSslCertificatePrivate::parseExtension(const QByteArray &data, QSslCertificateExtension *extension)
{
    bool ok;
    bool critical = false;
    QAsn1Element oidElem, valElem;

    QDataStream seqStream(data);

    // oid
    if (!oidElem.read(seqStream) || oidElem.type() != QAsn1Element::ObjectIdentifierType)
        return false;
    const QByteArray oid = oidElem.toObjectId();

    // critical and value
    if (!valElem.read(seqStream))
        return false;
    if (valElem.type() == QAsn1Element::BooleanType) {
        critical = valElem.toBool(&ok);
        if (!ok || !valElem.read(seqStream))
            return false;
    }
    if (valElem.type() != QAsn1Element::OctetStringType)
        return false;

    // interpret value
    QAsn1Element val;
    bool supported = true;
    QVariant value;
    if (oid == "1.3.6.1.5.5.7.1.1") {
        // authorityInfoAccess
        if (!val.read(valElem.value()) || val.type() != QAsn1Element::SequenceType)
            return false;
        QVariantMap result;
        const auto elems = val.toVector();
        for (const QAsn1Element &el : elems) {
            QVector<QAsn1Element> items = el.toVector();
            if (items.size() != 2)
                return false;
            const QString key = QString::fromLatin1(items.at(0).toObjectName());
            switch (items.at(1).type()) {
            case QAsn1Element::Rfc822NameType:
            case QAsn1Element::DnsNameType:
            case QAsn1Element::UniformResourceIdentifierType:
                result[key] = items.at(1).toString();
                break;
            }
        }
        value = result;
    } else if (oid == "2.5.29.14") {
        // subjectKeyIdentifier
        if (!val.read(valElem.value()) || val.type() != QAsn1Element::OctetStringType)
            return false;
        value = colonSeparatedHex(val.value()).toUpper();
    } else if (oid == "2.5.29.19") {
        // basicConstraints
        if (!val.read(valElem.value()) || val.type() != QAsn1Element::SequenceType)
            return false;

        QVariantMap result;
        QVector<QAsn1Element> items = val.toVector();
        if (items.size() > 0) {
            result[QStringLiteral("ca")] = items.at(0).toBool(&ok);
            if (!ok)
                return false;
        } else {
            result[QStringLiteral("ca")] = false;
        }
        if (items.size() > 1) {
            result[QStringLiteral("pathLenConstraint")] = items.at(1).toInteger(&ok);
            if (!ok)
                return false;
        }
        value = result;
    } else if (oid == "2.5.29.35") {
        // authorityKeyIdentifier
        if (!val.read(valElem.value()) || val.type() != QAsn1Element::SequenceType)
            return false;
        QVariantMap result;
        const auto elems = val.toVector();
        for (const QAsn1Element &el : elems) {
            if (el.type() == 0x80) {
                const QString key = QStringLiteral("keyid");
                result[key] = el.value().toHex();
            } else if (el.type() == 0x82) {
                const QString serial = QStringLiteral("serial");
                result[serial] = colonSeparatedHex(el.value());
            }
        }
        value = result;
    } else {
        supported = false;
        value = valElem.value();
    }

    extension->d->critical = critical;
    extension->d->supported = supported;
    extension->d->oid = QString::fromLatin1(oid);
    extension->d->name = QString::fromLatin1(oidElem.toObjectName());
    extension->d->value = value;

    return true;
}

QT_END_NAMESPACE
