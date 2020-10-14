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
#include "domain.h"
#include "connection.h"

#include "virtlyst.h"
#include "storagepool.h"
#include "storagevol.h"
#include "network.h"
#include "domainsnapshot.h"

#include <QTextStream>
#include <QDomElement>
#include <QFileInfo>
#include <QEventLoop>
#include <QDateTime>
#include <QTimer>
#include <QThread>
#include <QXmlStreamWriter>

#include <QLoggingCategory>

#include <sys/time.h>



Q_LOGGING_CATEGORY(VIRT_DOM, "virt.domain")

Domain::Domain(virDomainPtr domain, Connection *conn, QObject *parent) : QObject(parent)
  , m_conn(conn)
  , m_domain(domain)
{

}

Domain::~Domain()
{
    virDomainFree(m_domain);
}


QStringList Domain::getErrors(){
   QStringList err=m_conn->getErrors();
//   qDebug() << err;
   return err;
}

void Domain::delErrors(){
   m_conn->delErrors();
}



char * MetaDataLine(const char *elem)
{
        time_t rawtime;
        struct tm * timeinfo;
        static char buffer[80];

        time (&rawtime);
        timeinfo = localtime(&rawtime);
        strftime(buffer,sizeof(buffer),"%d-%m-%Y %H:%M:%S",timeinfo);
        return (QString("<%1>%2</%3>").arg(elem).arg(buffer).arg(elem).toUtf8().data());
        //return (const_cast<char*> (QString("<%1>%2</%3>").arg(elem).arg(buffer).arg(elem).toStdString().c_str()));
}


bool Domain::saveXml(bool update_creationTime)
{
    const QString xmlData = xmlDoc().toString(0);
    m_xml.clear();
//    qCDebug(VIRT_DOM) << xmlData;
    return m_conn->domainDefineXml(xmlData,false,false,false,false,update_creationTime);
}

QString Domain::xml()
{
    return xmlDoc().toString(2);
}

QString Domain::name() const
{
    const char *name = virDomainGetName(m_domain);
    if (!name) {
        qCWarning(VIRT_DOM) << "Failed to get domain name";
        return QString();
    }
    return QString::fromUtf8(name);
}

QString Domain::uuid()
{
    return dataFromSimpleNode(QStringLiteral("uuid"));
}

QString Domain::title()
{
    return dataFromSimpleNode(QStringLiteral("title"));
}

void Domain::setTitle(const QString &title)
{
    setDataToSimpleNode(QStringLiteral("title"), title);
}

QString Domain::description()
{
    return dataFromSimpleNode(QStringLiteral("description"));
}

void Domain::setDescription(const QString &description)
{
    setDataToSimpleNode(QStringLiteral("description"), description);
}

int Domain::status()
{
    if (!m_gotInfo) {
        if (virDomainGetInfo(m_domain, &m_info) < 0) {
            qCWarning(VIRT_DOM) << "Failed to get info for domain" << name();
            return -1;
        }
        m_gotInfo = true;
    }
    return m_info.state;
}

int Domain::currentVcpu()
{
    QDomElement docElem = xmlDoc().documentElement();
    QDomElement node = docElem.firstChildElement(QStringLiteral("vcpu"));
    if (node.hasAttribute(QStringLiteral("current"))) {
        return node.attribute(QStringLiteral("current")).toInt();
    }
    QDomNode data = node.firstChild();
    return data.nodeValue().toInt();
}


bool Domain::useUEFI()
{
    QDomDocument doc = xmlDoc();
    QDomElement os = doc
            .documentElement()
            .firstChildElement(QStringLiteral("os"))
            .firstChildElement(QStringLiteral("loader"));

    if ( !os.isNull())
        return true;
    return false;	

}

void Domain::setUEFI(bool yes){

    QDomDocument doc = xmlDoc();
    QDomElement os = doc
            .documentElement();

    QDomElement oselem= os.firstChildElement(QStringLiteral("os"));
    if ( useUEFI() && !yes){
         
         QDomElement  elem = oselem.firstChildElement(QStringLiteral("loader"));
	 oselem.removeChild(elem);
         elem = oselem.firstChildElement(QStringLiteral("vmram"));
	 oselem.removeChild(elem);
	 return;
	 }
    else if ( !useUEFI() && yes){
         QDomElement node,node1;
         node = doc.createElement(QStringLiteral("loader"));
	 node.setAttribute(QStringLiteral("readonly"), "yes");
	 node.setAttribute(QStringLiteral("type"), "pflash");
	 node.setAttribute(QStringLiteral("secure"), "no");
         node.appendChild(doc.createTextNode("/usr/share/OVMF/OVMF_CODE.fd"));
         oselem.appendChild(node);
         // node = doc.createElement(QStringLiteral("nvram"));
         // node.appendChild(doc.createTextNode("/var/lib/libvirt/nvram/guest_VARS.fd"));
         // oselem.appendChild(node);
	 return;
         }

    return; 	 
        

}

void  Domain::setDiskDevForBus(const QString &disk_dev,const QString &disk_bus, const QString &disk_source,const QString &disk_boot_from)
{   
    QDomDocument doc = xmlDoc();
    QDomElement source;
    QDomElement disk = doc
            .documentElement()
            .firstChildElement(QStringLiteral("devices"))
            .firstChildElement(QStringLiteral("disk"));
    QDomElement bus ;
    while (!disk.isNull()) {
        if (disk.attribute(QStringLiteral("device")) == QLatin1String("disk")) { 
	   bus = disk.firstChildElement(QStringLiteral("target"));
	   const QString dev = bus.attribute(QStringLiteral("dev"));
           if ( dev == disk_dev ) {
	      QDomElement driver = disk.firstChildElement(QStringLiteral("driver"));
              StorageVol *vol = m_conn->getStorageVolByPath(disk_source, this);
              QString new_disk_type=vol->type();
              if (new_disk_type == "iso" )
                      new_disk_type="raw";
	      driver.setAttribute(QStringLiteral("type"),new_disk_type);	   
              source = disk.firstChildElement(QStringLiteral("source"));
              source.setAttribute(QStringLiteral("file"),disk_source);
	      if (disk_boot_from == "on" ){
	         RemoveOsBoot();
                 QDomElement boot = disk.firstChildElement(QStringLiteral("boot"));
                    if (boot.isNull()){
                           boot = doc.createElement(QStringLiteral("boot"));
                           disk.appendChild(boot);
                        }
                      boot.setAttribute(QStringLiteral("order"),QStringLiteral("%1").arg((dev.at(2).toLatin1() & 0x0F)+2));
                     }
                     else {
                      QDomElement boot = disk.firstChildElement(QStringLiteral("boot"));
                      if (!boot.isNull()){
                          disk.removeChild(boot);
			   }
                          }
	      if (bus.attribute(QStringLiteral("bus")) != disk_bus ) {
              QDomElement address = disk.firstChildElement(QStringLiteral("address"));
	      disk.removeChild(address);
    	      bus.setAttribute(QStringLiteral("bus"), disk_bus);

              return;
            }
	   } 
        }
      disk = disk.nextSiblingElement(QStringLiteral("disk"));
    }

}



void Domain::RemoveNic(const QString &network_mac)
{
    QDomDocument doc = xmlDoc();
    QDomElement interface = doc
            .documentElement()
            .firstChildElement(QStringLiteral("devices"))
            .firstChildElement(QStringLiteral("interface"));
    while (!interface.isNull()) {
        if (interface.attribute(QStringLiteral("type")) == QLatin1String("network")) {
            if (interface.firstChildElement(QStringLiteral("mac")).attribute(QStringLiteral("address")) == network_mac) {
              interface.parentNode().removeChild(interface);
              return;
           }
           }
     interface = interface.nextSiblingElement(QStringLiteral("interface"));
    }

}


void Domain::RemoveDisk(const QString &disk_dev)
{
    QDomDocument doc = xmlDoc();
    QDomElement disk = doc
            .documentElement()
            .firstChildElement(QStringLiteral("devices"))
            .firstChildElement(QStringLiteral("disk"));
    QDomElement bus ;
    while (!disk.isNull()) {
        if (disk.attribute(QStringLiteral("device")) == QLatin1String("disk")) {
	   bus = disk.firstChildElement(QStringLiteral("target"));
           const QString dev = bus.attribute(QStringLiteral("dev"));
           if ( dev == disk_dev ){ 
              disk.parentNode().removeChild(disk);
              return;
	   }   
           }
      disk = disk.nextSiblingElement(QStringLiteral("disk"));
    }

}

void Domain::setNetworkTypeForMac(const QString &network_mac,const QString &network_type,const QString &network_source)
{

    QDomDocument doc = xmlDoc();
    QDomElement interface = doc
            .documentElement()
            .firstChildElement(QStringLiteral("devices"))
            .firstChildElement(QStringLiteral("interface"));
    while (!interface.isNull()) {
	if (interface.attribute(QStringLiteral("type")) == QLatin1String("network")) {
            if (interface.firstChildElement(QStringLiteral("mac")).attribute(QStringLiteral("address")) == network_mac) {
	      QDomElement model = interface.firstChildElement(QStringLiteral("model"));
              model.setAttribute(QStringLiteral("type"),network_type);
	      QDomElement source = interface.firstChildElement(QStringLiteral("source"));
              source.setAttribute(QStringLiteral("network"),network_source);
	      return;
	    }
	}
	interface = interface.nextSiblingElement(QStringLiteral("interface"));
    } 	

}


void Domain::setCurrentVcpu(int number)
{
    QDomElement docElem = xmlDoc().documentElement();
    QDomElement node = docElem.firstChildElement(QStringLiteral("vcpu"));
    node.setAttribute(QStringLiteral("current"), number);
}

int Domain::vcpu()
{
    return dataFromSimpleNode(QStringLiteral("vcpu")).toInt();
}

void Domain::setVcpu(int number)
{
    setDataToSimpleNode(QStringLiteral("vcpu"), QString::number(number));
}

quint64 Domain::memory()
{
    return dataFromSimpleNode(QStringLiteral("memory")).toULongLong();
}

void Domain::setMemory(quint64 kBytes)
{
    setDataToSimpleNode(QStringLiteral("memory"), QString::number(kBytes));
}

quint64 Domain::memoryMiB()
{
    return memory() / 1024;
}

quint64 Domain::currentMemory()
{
    return dataFromSimpleNode(QStringLiteral("currentMemory")).toULongLong();
}

void Domain::setCurrentMemory(quint64 kBytes)
{
    qCritical() << Q_FUNC_INFO << QString::number(kBytes) << kBytes;
    setDataToSimpleNode(QStringLiteral("currentMemory"), QString::number(kBytes));
}

quint64 Domain::currentMemoryMiB()
{
    return currentMemory() / 1024;
}

QString Domain::currentMemoryPretty()
{
    return Virtlyst::prettyKibiBytes(currentMemory());
}

bool Domain::hasManagedSaveImage() const
{
    return virDomainHasManagedSaveImage(m_domain, 0);
}

bool Domain::autostart() const
{
    int autostart = 0;
    if (virDomainGetAutostart(m_domain, &autostart) < 0) {
        qWarning() << "Failed to get autostart for domain" << name();
    }
    return autostart;
}
int Domain::AddNic(const QString &nic_bus,const QString &nic_network)
{

    QByteArray output;
    QXmlStreamWriter stream(&output);

    stream.writeStartElement(QStringLiteral("interface"));
    stream.writeAttribute(QStringLiteral("type"), QStringLiteral("network"));
    stream.writeEmptyElement(QStringLiteral("source"));
    stream.writeAttribute(QStringLiteral("network"), nic_network);
    stream.writeEmptyElement(QStringLiteral("model"));
    stream.writeAttribute(QStringLiteral("type"), nic_bus);
    stream.writeEndElement();
    AssignMetadata("lastModificationTime");
    return (virDomainAttachDeviceFlags(m_domain,output,VIR_DOMAIN_AFFECT_CONFIG));



}

int Domain::AddDisk(const QString &disk_source,const QString &disk_type,const QString &bus_type)
{
// qDebug() << disk_source << disk_type << bus_type;
    QByteArray output;
    QXmlStreamWriter stream(&output);

    stream.writeStartElement(QStringLiteral("disk"));
    stream.writeAttribute(QStringLiteral("device"), QStringLiteral("disk"));
    stream.writeAttribute(QStringLiteral("type"), QStringLiteral("file"));

    stream.writeEmptyElement(QStringLiteral("driver"));
    stream.writeAttribute(QStringLiteral("name"), QStringLiteral("qemu"));
    stream.writeAttribute(QStringLiteral("type"), disk_type);
    stream.writeEmptyElement(QStringLiteral("source"));
    stream.writeAttribute(QStringLiteral("file"), disk_source);

    stream.writeEmptyElement(QStringLiteral("target"));

    QDomDocument doc = xmlDoc();
    QDomElement source;
    QDomElement disk = doc
            .documentElement()
            .firstChildElement(QStringLiteral("devices"))
            .firstChildElement(QStringLiteral("disk"));
    QDomElement bus ;
    
    QList<QString> existing ;
    QString disk_prefix;
    
    //if (bus_type == "virtio" ) 
    disk_prefix="vd";
    //else
    //    disk_prefix="sd";
    
    while (!disk.isNull()) {
        if (disk.attribute(QStringLiteral("device")) == QLatin1String("disk")) {
           bus = disk.firstChildElement(QStringLiteral("target"));
	   if (disk_prefix == bus.attribute(QStringLiteral("dev")).mid(0,2))
	        existing.append(bus.attribute(QStringLiteral("dev")).mid(2,1));
	 }  
     disk = disk.nextSiblingElement(QStringLiteral("disk"));
     }

     QString alph = "abcdefghijklmnopqrstuvwxyz";  
     int i=0; 
     while (i < alph.size()){
       if ((existing.indexOf(alph.mid(i,1))) == -1)
	  break;
       i++;	  
     }	  


    stream.writeAttribute(QStringLiteral("bus"), bus_type);
    stream.writeAttribute(QStringLiteral("dev"), disk_prefix + alph.mid(i,1));

     stream.writeEndElement();
     AssignMetadata("lastModificationTime");
     return (virDomainAttachDeviceFlags(m_domain,output,VIR_DOMAIN_AFFECT_CONFIG));
        

}


bool Domain::snapshot(const QString &name)
{
    QDomDocument orig = xmlDoc();

    QDomDocument newDoc;
    QDomElement e = newDoc.createElement(QStringLiteral("domainsnapshot"));
    QDomElement node;

    node = newDoc.createElement(QStringLiteral("name"));
    node.appendChild(newDoc.createTextNode(name));
    e.appendChild(node);

    node = newDoc.createElement(QStringLiteral("creationTime"));
    node.appendChild(newDoc.createTextNode(QString::number(QDateTime::currentMSecsSinceEpoch() / 1000)));
    e.appendChild(node);

    node = newDoc.createElement(QStringLiteral("state"));
    node.appendChild(newDoc.createTextNode(QStringLiteral("shutoff")));
    e.appendChild(node);

    node = newDoc.createElement(QStringLiteral("active"));
    node.appendChild(newDoc.createTextNode(QStringLiteral("0")));
    e.appendChild(node);

    e.appendChild(orig.cloneNode(true));

    newDoc.appendChild(e);
// qCDebug(VIRT_DOM) <<  newDoc.toString(0).toUtf8().constData();
    virDomainSnapshotPtr snapshot = virDomainSnapshotCreateXML(m_domain, newDoc.toString(0).toUtf8().constData(), 0);
    if (snapshot) {
        virDomainSnapshotFree(snapshot);
        return true;
    }
    return false;
}

QVariantList Domain::snapshots()
{
    QVariantList ret;
    auto it = m_cache.constFind(QStringLiteral("snapshots"));
    if (it != m_cache.constEnd()) {
        ret = it.value().toList();
        return ret;
    }

    virDomainSnapshotPtr *snaps;
    int count = virDomainListAllSnapshots(m_domain, &snaps, 0);
    if (count == -1) {
        return ret;
    }

    for (int i = 0; i < count; ++i) {
        auto snap = new DomainSnapshot(snaps[i], this);
        ret.append(QVariant::fromValue(snap));
    }
    free(snaps);

    m_cache.insert(QStringLiteral("snapshots"), ret);
    return ret;
}

DomainSnapshot *Domain::getSnapshot(const QString &name)
{
    virDomainSnapshotPtr snap = virDomainSnapshotLookupByName(m_domain, name.toUtf8().constData(), 0);
    if (!snap) {
        return nullptr;
    }
    return new DomainSnapshot(snap, this);
}

QString Domain::consoleType()
{
    return xmlDoc().documentElement()
            .firstChildElement(QStringLiteral("devices"))
            .firstChildElement(QStringLiteral("graphics"))
            .attribute(QStringLiteral("type"));
}

void Domain::setConsoleType(const QString &type)
{
    xmlDoc().documentElement()
            .firstChildElement(QStringLiteral("devices"))
            .firstChildElement(QStringLiteral("graphics"))
            .setAttribute(QStringLiteral("type"), type);
}

QString Domain::consolePassword()
{
    return xmlDoc().documentElement()
            .firstChildElement(QStringLiteral("devices"))
            .firstChildElement(QStringLiteral("graphics"))
            .attribute(QStringLiteral("passwd"));
}

void Domain::setConsolePassword(const QString &password)
{
    xmlDoc().documentElement()
            .firstChildElement(QStringLiteral("devices"))
            .firstChildElement(QStringLiteral("graphics"))
            .setAttribute(QStringLiteral("passwd"), password);
}

quint16 Domain::consolePort()
{
    return static_cast<quint16>(xmlDoc().documentElement()
                                .firstChildElement(QStringLiteral("devices"))
                                .firstChildElement(QStringLiteral("graphics"))
                                .attribute(QStringLiteral("port")).toUInt());
}

QString Domain::consoleListenAddress()
{
    QString ret = xmlDoc().documentElement()
                .firstChildElement(QStringLiteral("devices"))
                .firstChildElement(QStringLiteral("graphics"))
                .attribute(QStringLiteral("listen"));
    if (ret.isEmpty()) {
        ret = xmlDoc().documentElement()
                .firstChildElement(QStringLiteral("devices"))
                .firstChildElement(QStringLiteral("graphics"))
                .firstChildElement(QStringLiteral("listen"))
                .attribute(QStringLiteral("address"));
        if (ret.isEmpty()) {
            return QStringLiteral("127.0.0.1");
        }
    }
    return ret;
}

QString Domain::consoleKeymap()
{
    return xmlDoc().documentElement()
            .firstChildElement(QStringLiteral("devices"))
            .firstChildElement(QStringLiteral("graphics"))
            .attribute(QStringLiteral("keymap"));
}

void Domain::setConsoleKeymap(const QString &keymap)
{
    xmlDoc().documentElement()
            .firstChildElement(QStringLiteral("devices"))
            .firstChildElement(QStringLiteral("graphics"))
            .setAttribute(QStringLiteral("keymap"), keymap);
}
struct GetNetUsage
{
    GetNetUsage(const QStringList &networks, virDomainPtr dom) : m_networks(networks), m_dom(dom) {}

    void begin() {
        for (const QString &net : m_networks) {
            virDomainInterfaceStatsStruct stats;
            qint64 rx = 0;
            qint64 tx = 0;
            if (virDomainInterfaceStats(m_dom, net.toUtf8().constData(), &stats, sizeof(virDomainInterfaceStatsStruct)) == 0) {
                if (stats.rx_bytes != -1) {
                    rx = stats.rx_bytes;
                }
                if (stats.tx_bytes != -1) {
                    tx = stats.tx_bytes;
                }
            }
            ret.append({ rx, tx });
        }
    }

    QVector<std::pair<qint64, qint64> > compute() {
        int i = 0;
        for (const QString &net : m_networks) {
            virDomainInterfaceStatsStruct stats;
            std::pair<qint64, qint64> rx_tx = ret[i];
            qint64 rx = 0;
            qint64 tx = 0;
            if (virDomainInterfaceStats(m_dom, net.toUtf8().constData(), &stats, sizeof(virDomainInterfaceStatsStruct)) == 0) {
                if (stats.rx_bytes != -1) {
                    rx = (stats.rx_bytes - rx_tx.first) * 8 / 1024 / 1024;
                }
                if (stats.tx_bytes != -1) {
                    tx = (stats.tx_bytes - rx_tx.second) * 8 / 1024 / 1024;
                }
            }
            ret[i++] = { rx, tx };
        }
        return ret;
    }

    const QStringList m_networks;
    virDomainPtr m_dom;
    QVector<std::pair<qint64, qint64> > ret;
};

QVector<std::pair<qint64, qint64> > Domain::netUsageMiBs()
{
    getStats();

    return m_netUsageMiBs;
}

struct GetHddUsage
{
    GetHddUsage(const QStringList &devices, virDomainPtr dom) : m_devices(devices), m_dom(dom) {}

    void begin() {
        for (const QString &dev : m_devices) {
            virDomainBlockStatsStruct stats;
            qint64 rd = 0;
            qint64 wr = 0;
            if (virDomainBlockStats(m_dom, dev.toUtf8().constData(), &stats, sizeof(virDomainBlockStatsStruct)) == 0) {
                if (stats.rd_bytes != -1) {
                    rd = stats.rd_bytes;
                }
                if (stats.wr_bytes != -1) {
                    wr = stats.wr_bytes;
                }
            }
            ret.insert(dev, { rd, wr });
        }
    }

    QMap<QString, std::pair<qint64, qint64> > compute() {
        for (const QString &dev : m_devices) {
            virDomainBlockStatsStruct stats;
            std::pair<qint64, qint64> rd_wr = ret[dev];
            qint64 rd = 0;
            qint64 wr = 0;
            if (virDomainBlockStats(m_dom, dev.toUtf8().constData(), &stats, sizeof(virDomainBlockStatsStruct)) == 0) {
                if (stats.rd_bytes != -1) {
                    rd = (stats.rd_bytes - rd_wr.first) * 8 / 1024 / 1024;
                }
                if (stats.wr_bytes != -1) {
                    wr = (stats.wr_bytes - rd_wr.second) * 8 / 1024 / 1024;
                }
            }
            ret[dev] = { rd, wr };
        }

        return ret;
    }

    const QStringList m_devices;
    virDomainPtr m_dom;
    QMap<QString, std::pair<qint64, qint64> > ret;
};

QMap<QString, std::pair<qint64, qint64> > Domain::hddUsageMiBs()
{
    getStats();

    return m_hddUsageMiBs;
}

QStringList Domain::blkDevices()
{
    QStringList ret;
    auto it = m_cache.constFind(QStringLiteral("blkDevices"));
    if (it != m_cache.constEnd()) {
        ret = it.value().toStringList();
        return ret;
    }

    QDomElement disk = xmlDoc()
            .documentElement()
            .firstChildElement(QStringLiteral("devices"))
            .firstChildElement(QStringLiteral("disk"));
    while (!disk.isNull()) {
        QString dev_file;
        bool network_disk = true;

        const QDomElement source = disk.firstChildElement(QStringLiteral("source"));

        if (source.hasAttribute(QStringLiteral("protocol"))) {
            dev_file = source.attribute(QStringLiteral("protocol"));
            network_disk = true;
        }
        if (source.hasAttribute(QStringLiteral("file"))) {
            dev_file = source.attribute(QStringLiteral("file"));
        }
        if (source.hasAttribute(QStringLiteral("dev"))) {
            dev_file = source.attribute(QStringLiteral("dev"));
        }
        const QString dev_bus = disk.firstChildElement(QStringLiteral("target")).attribute(QStringLiteral("dev"));

        if (!dev_file.isEmpty() && !dev_bus.isEmpty()) {
            if (network_disk) {
                // this will always be true, odd logic from webvirtmgr
                dev_file = dev_bus;
            }
            ret.append(dev_file);
        }

        disk = disk.nextSiblingElement(QStringLiteral("disk"));
    }

    m_cache.insert(QStringLiteral("blkDevices"), ret);
    return ret;
}

bool Domain::can_take_snapshots()
{
    return m_can_take_snapshots;
}


QVariantList Domain::disks()
{
    QVariantList ret;
    auto it = m_cache.constFind(QStringLiteral("disks"));
    if (it != m_cache.constEnd()) {
        ret = it.value().toList();
        return ret;
    }

    QDomElement disk = xmlDoc()
            .documentElement()
            .firstChildElement(QStringLiteral("devices"))
            .firstChildElement(QStringLiteral("disk"));
    if (!disk.isNull()) 
        m_can_take_snapshots=true; 	    
    while (!disk.isNull()) {
        if (disk.attribute(QStringLiteral("device")) == QLatin1String("disk")) {
            const QString dev = disk.firstChildElement(QStringLiteral("target")).attribute(QStringLiteral("dev"));
            const QString bus = disk.firstChildElement(QStringLiteral("target")).attribute(QStringLiteral("bus"));
            const QString srcFile = disk.firstChildElement(QStringLiteral("source")).attribute(QStringLiteral("file"));
            const QString diskFormat = disk.firstChildElement(QStringLiteral("driver")).attribute(QStringLiteral("type"));
	    if ( diskFormat != "qcow2" ) 
	         m_can_take_snapshots = false;
            const QString bootorder = disk.firstChildElement(QStringLiteral("boot")).attribute(QStringLiteral("order"));
            QString volume;
            QString storage;
            if (!srcFile.isEmpty()) {
                StorageVol *vol = m_conn->getStorageVolByPath(srcFile, this);
                if (vol) {
                    volume = vol->name();
                    StoragePool *pool = vol->pool();
                    if (pool) {
                        storage = pool->name();
                    }
                }
            }

            QHash<QString, QString> data{
                {QStringLiteral("dev"), dev},
                {QStringLiteral("bus"), bus},
                {QStringLiteral("image"), volume},
                {QStringLiteral("storage"), storage},
                {QStringLiteral("path"), srcFile},
                {QStringLiteral("format"), diskFormat},
                {QStringLiteral("bootorder"), bootorder},
            };
            ret.append(QVariant::fromValue(data));
        }
        disk = disk.nextSiblingElement(QStringLiteral("disk"));
    }

    m_cache.insert(QStringLiteral("disks"), ret);
    return ret;
}

QVariantList Domain::cloneDisks()
{
    QVariantList ret;
    auto it = m_cache.constFind(QStringLiteral("cloneDisks"));
    if (it != m_cache.constEnd()) {
        ret = it.value().toList();
        return ret;
    }

    const QVariantList _disks = disks();
    for (const QVariant &var : _disks) {
        QHash<QString, QString> disk = var.value<QHash<QString, QString> >();
        QString image = disk.value(QStringLiteral("image"));
        if (image.isEmpty()) {
            continue;
        }

        if (image.contains(QLatin1Char('.'))) {
            QFileInfo info(image);
            if (info.path() == QLatin1String(".")) {
                disk[QStringLiteral("image")] = info.baseName() + QLatin1String("-clone.") + info.completeSuffix();
            } else {
                disk[QStringLiteral("image")] = info.path() + QLatin1Char('/') + info.baseName() + QLatin1String("-clone.") + info.completeSuffix();
            }
        } else {
            disk[QStringLiteral("image")] = image + QLatin1String("-clone");
        }
        ret.append(QVariant::fromValue(disk));
    }

    m_cache.insert(QStringLiteral("cloneDisks"), ret);
    return ret;
}

QVariantList Domain::media()
{
    QVariantList ret;
    auto it = m_cache.constFind(QStringLiteral("media"));
    if (it != m_cache.constEnd()) {
        ret = it.value().toList();
        return ret;
    }

    QDomElement disk = xmlDoc()
            .documentElement()
            .firstChildElement(QStringLiteral("devices"))
            .firstChildElement(QStringLiteral("disk"));
    while (!disk.isNull()) {
        if (disk.attribute(QStringLiteral("device")) == QLatin1String("cdrom")) {
            const QString dev = disk.firstChildElement(QStringLiteral("target")).attribute(QStringLiteral("dev"));
            const QString srcFile = disk.firstChildElement(QStringLiteral("source")).attribute(QStringLiteral("file"));
            const QString bootorder = disk.firstChildElement(QStringLiteral("boot")).attribute(QStringLiteral("order"));
            QString volume;
            QString storage;
            if (!srcFile.isEmpty()) {
                StorageVol *vol = m_conn->getStorageVolByPath(srcFile, this);
                if (vol) {
                    volume = vol->name();
                    StoragePool *pool = vol->pool();
                    if (pool) {
                        storage = pool->name();
                    }
                }
            }

            QHash<QString, QString> data{
                {QStringLiteral("dev"), dev},
                {QStringLiteral("image"), volume},
                {QStringLiteral("storage"), storage},
                {QStringLiteral("path"), srcFile},
                {QStringLiteral("bootorder"), bootorder},
            };
            ret.append(QVariant::fromValue(data));
        }
        disk = disk.nextSiblingElement(QStringLiteral("disk"));
    }

    m_cache.insert(QStringLiteral("media"), ret);
    return ret;
}

QVariantList Domain::networks()
{
    QVariantList ret;
    auto it = m_cache.constFind(QStringLiteral("networks"));
    if (it != m_cache.constEnd()) {
        ret = it.value().toList();
        return ret;
    }

    QDomElement interface = xmlDoc()
            .documentElement()
            .firstChildElement(QStringLiteral("devices"))
            .firstChildElement(QStringLiteral("interface"));
    while (!interface.isNull()) {
        const QString macHost = interface.firstChildElement(QStringLiteral("mac")).attribute(QStringLiteral("address"));
        const QString type = interface.firstChildElement(QStringLiteral("model")).attribute(QStringLiteral("type"));
        const QString alias = interface.firstChildElement(QStringLiteral("alias")).attribute(QStringLiteral("name"));
        const QDomElement source = interface.firstChildElement(QStringLiteral("source"));
        QString nicHost;
        if (source.hasAttribute(QStringLiteral("network"))) {
            nicHost = source.attribute(QStringLiteral("network"));
        } else if (source.hasAttribute(QStringLiteral("bridge"))) {
            nicHost = source.attribute(QStringLiteral("bridge"));
        } else if (source.hasAttribute(QStringLiteral("dev"))) {
            nicHost = source.attribute(QStringLiteral("dev"));
        }

        QString ip;
        Network *net = m_conn->getNetwork(nicHost, this);
        if (net) {
            ip = net->ipAddressForMac(macHost);
        }

        QHash<QString, QString> data{
            {QStringLiteral("mac"), macHost},
            {QStringLiteral("nic"), nicHost},
            {QStringLiteral("ip"), ip},
            {QStringLiteral("type"), type},
            {QStringLiteral("alias"), alias},
        };
        ret.append(QVariant::fromValue(data));
        interface = interface.nextSiblingElement(QStringLiteral("interface"));
    }

    m_cache.insert(QStringLiteral("networks"), ret);
    return ret;
}

QStringList Domain::networkTargetDevs()
{
    QStringList ret;
    auto it = m_cache.constFind(QStringLiteral("networkTargetDevs"));
    if (it != m_cache.constEnd()) {
        ret = it.value().toStringList();
        return ret;
    }

    QDomElement interface = xmlDoc()
            .documentElement()
            .firstChildElement(QStringLiteral("devices"))
            .firstChildElement(QStringLiteral("interface"));
    while (!interface.isNull()) {
        const QDomElement target = interface.firstChildElement(QStringLiteral("target"));
        if (target.hasAttribute(QStringLiteral("dev"))) {
            ret.append(target.attribute(QStringLiteral("dev")));
        }

        interface = interface.nextSiblingElement(QStringLiteral("interface"));
    }

    m_cache.insert(QStringLiteral("networkTargetDevs"), ret);
    return ret;
}

bool Domain::start()
{


    return virDomainCreate(m_domain) == 0  ? true : false;
}

void Domain::shutdown()
{
     virDomainShutdown(m_domain);
     int i=0;  
     m_gotInfo=false; 
     while (i<=30 && status() == VIR_DOMAIN_RUNNING) {
       m_gotInfo=false; 
    	   QThread::sleep(1);
	   i++;
       }	   
     m_gotInfo=false;
     if (status() == VIR_DOMAIN_RUNNING) 
        virDomainDestroy(m_domain);
}

void Domain::suspend()
{
    virDomainSuspend(m_domain);
}

bool Domain::resume()
{
    if ( virDomainResume(m_domain) == 0)
       return true;
    else
       return false;
}

void Domain::destroy()
{
    virDomainDestroy(m_domain);
}

void Domain::reset()
{
    virDomainReset(m_domain,0);
}

void Domain::undefine()
{
    virDomainUndefineFlags(m_domain,VIR_DOMAIN_UNDEFINE_MANAGED_SAVE | VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA | VIR_DOMAIN_UNDEFINE_NVRAM | VIR_DOMAIN_UNDEFINE_CHECKPOINTS_METADATA);
}

void Domain::managedSave()
{
    virDomainManagedSave(m_domain, 0);
}

void Domain::managedSaveRemove()
{
    virDomainManagedSaveRemove(m_domain, 0);
}

void Domain::setAutostart(bool enable)
{
    virDomainSetAutostart(m_domain, enable ? 1 : 0);
}

//bool Domain::attachDevice(const QString &xml)
//{
//    m_xml.clear();
//    return virDomainAttachDevice(m_domain, xml.toUtf8().constData()) == 0;
//}
//
bool Domain::updateDevice(const QString &xml, uint flags)
{
    m_xml.clear();
    return virDomainUpdateDeviceFlags(m_domain, xml.toUtf8().constData(), flags) == 0;
}

//QDebug operator<<(QDebug dbg, const QDomNode& node)
//{
//  QString s;
//  QTextStream str(&s, QIODevice::WriteOnly);
//  node.save(str, 2);
//  dbg << qPrintable(s);
//  return dbg;
//}


QDomElement Domain::RemoveOsBoot()
{
    QDomDocument doc = xmlDoc();
    QDomElement os = doc
            .documentElement()
            .firstChildElement(QStringLiteral("os"));
    QDomElement boot = os.firstChildElement(QStringLiteral("boot"));
    if (!boot.isNull())
          boot.parentNode().removeChild(boot);
    return os;
}


bool Domain::mountIso(const QString &dev, const QString &image, const QString &bootorder)
{
// qDebug() << dev << image << bootorder;
    bool ret=false;
    QDomElement os;
    QDomDocument doc = xmlDoc();
    QDomElement disk = doc
            .documentElement()
            .firstChildElement(QStringLiteral("devices"))
            .firstChildElement(QStringLiteral("disk"));
    while (!disk.isNull()) {
        if (disk.attribute(QStringLiteral("device")) == QLatin1String("cdrom")) {
		if(disk.firstChildElement(QStringLiteral("target")).attribute(QStringLiteral("dev")) == dev) {
		
                QDomElement source = disk.firstChildElement(QStringLiteral("source"));
                if (source.isNull()) {
                    source = doc.createElement(QStringLiteral("source"));
                    disk.appendChild(source);
                }
                source.setAttribute(QStringLiteral("file"), image);
                if (bootorder == "on") {
                    os=RemoveOsBoot();
		    QDomElement boot = disk.firstChildElement(QStringLiteral("boot"));
		    if (boot.isNull()){
		           boot = doc.createElement(QStringLiteral("boot"));
                           disk.appendChild(boot);
			}
		   if (dev == "sdy") 
		           boot.setAttribute(QStringLiteral("order"), "1");	
	           else
		           boot.setAttribute(QStringLiteral("order"), "2");	
		      
		}

                
                QByteArray xml;
                QTextStream s(&xml);
                disk.parentNode().parentNode().save(s, 2);
		os.save(s,2);
// qDebug() << xml;		
                // ret = updateDevice(xml, VIR_DOMAIN_AFFECT_CONFIG);
		saveXml();
                break;
            }
	     
        }
        disk = disk.nextSiblingElement(QStringLiteral("disk"));
    }
  return ret;
}





void Domain::umountIso(const QString &dev, const QString &image)
{

    QDomElement disk = xmlDoc()
            .documentElement()
            .firstChildElement(QStringLiteral("devices"))
            .firstChildElement(QStringLiteral("disk"));
    while (!disk.isNull()) {
        if (disk.attribute(QStringLiteral("device")) == QLatin1String("cdrom")) {
            QDomElement source = disk.firstChildElement(QStringLiteral("source"));
            if (disk.firstChildElement(QStringLiteral("target")).attribute(QStringLiteral("dev")) == dev &&
                    source.attribute(QStringLiteral("file")) == image) {
                disk.removeChild(source);
                QDomElement boot = disk.firstChildElement(QStringLiteral("boot"));
		if (!boot.isNull())
		            disk.removeChild(boot);
                QByteArray xml;
                QTextStream s(&xml);
                disk.save(s, 2);
                bool ret = updateDevice(xml, VIR_DOMAIN_AFFECT_CONFIG);
		return;
            }
        }
        disk = disk.nextSiblingElement(QStringLiteral("disk"));
    }
//    saveXml();
}

QDomDocument Domain::xmlDoc()
{
    if (m_xml.isNull()) {
        char *xml = virDomainGetXMLDesc(m_domain, VIR_DOMAIN_XML_SECURE);
        const QString xmlString = QString::fromUtf8(xml);
        QString error;
        if (!m_xml.setContent(xmlString, &error)) {
            qWarning() << "Failed to parse XML from interface" << error;
        }
        free(xml);
    }
    return m_xml;
}

QString Domain::dataFromSimpleNode(const QString &element)
{
    return xmlDoc().documentElement()
            .firstChildElement(element)
            .firstChild()
            .nodeValue();
}

void Domain::setDataToSimpleNode(const QString &element, const QString &data)
{
    QDomDocument doc = xmlDoc();
    QDomElement elem = doc
            .documentElement()
            .firstChildElement(element);
    if (elem.isNull()) {
                QDomElement node;
                node=doc.createElement(element);
		node.appendChild(doc.createTextNode(data));
		elem= doc.firstChildElement(QStringLiteral("domain"));
                elem.appendChild(node); 

		}
    else		
    elem.firstChild()		
        .setNodeValue(data);		
}

int Domain::cpuUsage()
{
    if (!getStats()) {
        return -1;
    }
    return m_cpuUsage;
}

bool getCpuTime(virDomainPtr dom, int nparams, quint64 &cpu_time)
{
    virTypedParameter params[nparams];
    if (virDomainGetCPUStats(dom, params, uint(nparams), -1, 1, 0) != nparams) {
        return false;
    }
    for (int i = 0; i < nparams; ++i) {


        if ((strcmp(params[i].field, VIR_DOMAIN_CPU_STATS_CPUTIME) == 0 || strcmp(params[i].field, VIR_DOMAIN_CPU_STATS_VCPUTIME) == 0)
                && params[i].type == VIR_TYPED_PARAM_ULLONG) {
            cpu_time = params[i].value.ul;
            return true;
        }
    }
    return false;
}


struct GetCPUStats {
    GetCPUStats(virDomainPtr dom) : m_dom(dom) {
        m_nparams = virDomainGetCPUStats(dom, nullptr, 0, -1, 1, 0);
    }

    void getData(struct timeval &time, quint64 &stats) {
        if (m_nparams == -1) {
            return;
        }

        /* Get current time */
        if (gettimeofday(&time, nullptr) < 0) {
            qCritical("unable to get time");
            m_nparams = -1;
            return;
        }

        if (!getCpuTime(m_dom, m_nparams, stats)) {
            m_nparams = -1;
        }
    }

    void begin() {
        getData(then_t, then_stats);
    }

    double compute(int currentVcpu) {
        getData(now_t, now_stats);

        if (m_nparams<0 ) {
            return 0;
        }

        qint64 then = then_t.tv_sec * 1000000 + then_t.tv_usec;
        qint64 now = now_t.tv_sec * 1000000 + now_t.tv_usec;


        double usage = (now_stats - then_stats) / (now - then) / 10 / currentVcpu;
	if (usage > 100) usage=100;
        return usage;
    }

    int m_nparams;
    virDomainPtr m_dom;
    struct timeval then_t, now_t;
    quint64 then_stats, now_stats;
};



bool Domain::getStats()
{
    if (m_gotStats) {
        return true;
    }

    if (status() == VIR_DOMAIN_RUNNING) {
        GetCPUStats cpuStat(m_domain);
        GetNetUsage netUsage(networkTargetDevs(), m_domain);
        GetHddUsage hddUsage(blkDevices(), m_domain);

        cpuStat.begin();
        netUsage.begin();
        hddUsage.begin();

        QEventLoop loop;
        QTimer::singleShot(1000, &loop, &QEventLoop::quit);
        loop.exec();

        m_cpuUsage = int(cpuStat.compute(currentVcpu()));
        m_netUsageMiBs = netUsage.compute();
        m_hddUsageMiBs = hddUsage.compute();
    }

    m_gotStats = true;

    return true;
}


int Domain::AssignMetadata(const char *elem)
{

//return 0;

//    const struct metadatafc *test = data;
// qDebug() << elem << MetaDataLine(elem);
    if (virDomainSetMetadata(m_domain, VIR_DOMAIN_METADATA_ELEMENT,MetaDataLine(elem), elem, elem, VIR_DOMAIN_AFFECT_CURRENT) < 0)
        return -1;
    // qDebug() << virDomainGetMetadata(m_domain, VIR_DOMAIN_METADATA_ELEMENT, elem, VIR_DOMAIN_AFFECT_CURRENT);
    return 0;
}

QString Domain::creationTime()
{ 
     QByteArray xmlText=virDomainGetMetadata(m_domain, VIR_DOMAIN_METADATA_ELEMENT, "creationTime", VIR_DOMAIN_AFFECT_CURRENT);
     QDomDocument doc;
     doc.setContent(xmlText);
     QDomNodeList list=doc.elementsByTagName("creationTime");
     return list.at(0).toElement().text();
}

QString Domain::lastModificationTime()
{
     QByteArray xmlText=virDomainGetMetadata(m_domain, VIR_DOMAIN_METADATA_ELEMENT, "lastModificationTime", VIR_DOMAIN_AFFECT_CURRENT);
     if (xmlText.isNull()) return xmlText;
     QDomDocument doc;
     doc.setContent(xmlText);
     QDomNodeList list=doc.elementsByTagName("lastModificationTime");
     return list.at(0).toElement().text();
}
