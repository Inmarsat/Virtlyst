/*
 * Copyright (C) 2018 Daniel Nicoletti <dantti12@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include "storagevol.h"

#include "storagepool.h"
#include "virtlyst.h"
#include <QXmlStreamWriter>
#include <QLoggingCategory>

// #include <magic.h>

StorageVol::StorageVol(virStorageVolPtr vol, virStoragePoolPtr pool, QObject *parent) : QObject(parent)
  , m_vol(vol)
  , m_pool(pool)
{
}

QString StorageVol::name()
{
    return QString::fromUtf8(virStorageVolGetName(m_vol));
}

QString StorageVol::type()
{
    const QString ret = xmlDoc()
            .documentElement()
            .firstChildElement(QStringLiteral("target"))
            .firstChildElement(QStringLiteral("format"))
            .attribute(QStringLiteral("type"));
    if (ret == QLatin1String("unknown") || ret.isEmpty()) {
        return QStringLiteral("raw");
    }
    return ret;
}


QString StorageVol::r_size()
{
      if (getInfo()) 
        return QString::number(m_info.capacity);
	;
    return QString();
}

bool StorageVol::expandStorageVolume(const qint64 &increase_by)
{
   qint64 sizeByte = increase_by * 1073741824;
   if( virStorageVolResize(m_vol,sizeByte,VIR_STORAGE_VOL_RESIZE_DELTA) == 0)
      return true;
   else
      return false;
}

QString StorageVol::size()
{
    if (getInfo())
        return Virtlyst::prettyKibiBytes(m_info.capacity / 1024);
    return QString();
}


QString StorageVol::usedby()
{
    QString usedbyvm;
    QString pathdisk = path();
    QString tryname;
    QString trysrc;
    QVector<Domain *> ret;
    
    m_conn = virStorageVolGetConnect(m_vol);
    virDomainPtr *domains;
    int count = virConnectListAllDomains(m_conn, &domains, VIR_CONNECT_LIST_DOMAINS_ACTIVE | VIR_CONNECT_LIST_DOMAINS_INACTIVE);
    if (count > 0) {
        for (int i = 0; i < count; i++) {
            tryname = QString::fromUtf8(virDomainGetName(domains[i]));
            char *xml = virDomainGetXMLDesc(domains[i], VIR_DOMAIN_XML_SECURE);
            QString xmlString = QString::fromUtf8(xml);
            QString error;
            QDomDocument domxml;
            if (!domxml.setContent(xmlString, &error)) {
                qWarning() << "Failed to parse XML from interface" << error;
            }
            QDomElement disk = domxml
                    .documentElement()
                    .firstChildElement(QStringLiteral("devices"))
                    .firstChildElement(QStringLiteral("disk"));
            while (!disk.isNull()) {
                trysrc = disk.firstChildElement(QStringLiteral("source")).attribute(QStringLiteral("file"));
                if (trysrc == pathdisk){
                    usedbyvm = usedbyvm + tryname + QStringLiteral(" ");
                }
                disk = disk.nextSiblingElement(QStringLiteral("disk"));
            }
            free(xml);
        }
    }
    free(domains);
    return usedbyvm;
}

QString StorageVol::path()
{
    return QString::fromUtf8(virStorageVolGetPath(m_vol));
}

bool StorageVol::undefine(int flags)
{
    return virStorageVolDelete(m_vol, flags) == 0;
}

StorageVol *StorageVol::clone(const QString &name, const QString &format, int flags)
{
    QByteArray output;
    QXmlStreamWriter stream(&output);

    QString localFormat = format;
    if (format.isEmpty()) {
        localFormat = type();
    }

    stream.writeStartElement(QStringLiteral("volume"));
    stream.writeTextElement(QStringLiteral("name"), format != QLatin1String("dir") ? name : name + QLatin1String(".img"));
    stream.writeTextElement(QStringLiteral("capacity"), QStringLiteral("0"));
    stream.writeTextElement(QStringLiteral("allocation"), QStringLiteral("0"));

    stream.writeStartElement(QStringLiteral("target"));
    stream.writeStartElement(QStringLiteral("format"));
    stream.writeAttribute(QStringLiteral("type"), localFormat);
    stream.writeEndElement(); // format
    stream.writeStartElement(QStringLiteral("permissions"));
    stream.writeTextElement(QStringLiteral("mode"), QString::number(644));
    stream.writeTextElement(QStringLiteral("owner"), QString::number(1000));
    stream.writeTextElement(QStringLiteral("group"), QString::number(36));
    stream.writeEndElement(); // permissions
    stream.writeEndElement(); // target

    stream.writeEndElement(); // volume
    // qDebug() << "XML output" << output;

    virStorageVolPtr vol = virStorageVolCreateXMLFrom(poolPtr(), output.constData(), m_vol, flags);
    if (vol) {
        return new StorageVol(vol, m_pool, this);
    }
    return nullptr;
}


void StorageVol::upload(Cutelyst::Upload* upload)
{
  qDebug() << "uploading: " << upload->filename();
  qDebug() << "name: " << upload->name();
  qDebug() << "size: " << upload->size();
  qDebug() << "pos: " << upload->pos();
  qDebug() << "content-type: " << upload->contentType();

  m_conn = virStorageVolGetConnect(m_vol);
  virStreamPtr stream = virStreamNew(m_conn, 0);
  int status = virStorageVolUpload(m_vol, stream, 0, upload->size(), 0);
  qDebug() << "virStorageVolUpload status: " << status;

  char data[0x100000]; // 1MB buffer on the stack
  while (!upload->atEnd()) {
    int bytes = upload->read(data, sizeof(data));
//    qDebug() << upload->filename() << ": read " << bytes << " bytes";
    int written = 0;
    while (written < bytes) {
      int count = virStreamSend(stream, data, bytes);
      if (count < 0) {
        qDebug() << "Failed to write bytes to stream";
        virStreamAbort(stream);
        goto done;
      }
      // qDebug() << upload->filename() << ": wrote " << bytes << " bytes";
      written += count;
    }
  }
  qDebug() << "File uploading" << upload->filename() << "done";
  if (virStreamFinish(stream) < 0) {
    qDebug() << "Failed to finish writing virt stream";
  }
 done:
  virStreamFree(stream);

}

StoragePool *StorageVol::pool()
{
    return new StoragePool(poolPtr(), this);
}

bool StorageVol::getInfo()
{
    if (!m_gotInfo && virStorageVolGetInfo(m_vol, &m_info) == 0) {
        m_gotInfo = true;
    }
    return m_gotInfo;
}

QDomDocument StorageVol::xmlDoc()
{
    if (m_xml.isNull()) {
        char *xml = virStorageVolGetXMLDesc(m_vol, 0);
        const QString xmlString = QString::fromUtf8(xml);
        // qDebug() << "XML" << xml;
        QString error;
        if (!m_xml.setContent(xmlString, &error)) {
            qWarning() << "Failed to parse XML from interface" << error;
        }
        free(xml);
    }
    return m_xml;
}

virStoragePoolPtr StorageVol::poolPtr()
{
    if (!m_pool) {
        m_pool = virStoragePoolLookupByVolume(m_vol);
    }
    return m_pool;
}
