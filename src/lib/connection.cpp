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
#include "connection.h"

#include "virtlyst.h"
#include "domain.h"
#include "interface.h"
#include "network.h"
#include "nodedevice.h"
#include "storagepool.h"
#include "storagevol.h"

#include <libvirt/virterror.h>

#include <QUrl>
#include <QXmlStreamWriter>
#include <QTimer>
#include <QEventLoop>

#include <QLoggingCategory>


#include <Cutelyst/Plugins/StatusMessage>
#include <Cutelyst/Plugins/Utils/Sql>

#include <QSqlQuery>
#include <QSqlError>

#include <QUuid>
#include <math.h>
#include <QRegularExpression>
#include <string>
#include <regex>
#include <QThread>
// #include <QRandomGenerator>

Q_LOGGING_CATEGORY(VIRT_CONN, "virt.connection")
static QStringList m_libvirterr;
static int authCreds[] = {
    VIR_CRED_AUTHNAME,
    VIR_CRED_PASSPHRASE,
};

static double pround(double  num, int dec)
{
    double m = (num < 0.0) ? -1.0 : 1.0;   // check if input is negative
    double pwr = pow(10, dec);

    return double(floor((double)num * m * pwr + 0.5) / pwr) * m;
}

QString convert_version(unsigned long &hvVer)
{
    unsigned long  major, minor, release;
    major = hvVer / 1000000;
    hvVer %= 1000000;
    minor = hvVer / 1000;
    release = hvVer % 1000;

    return QString("%1.%2.%3").arg(major).arg(minor).arg(release);
}

static int authCb(virConnectCredentialPtr cred, unsigned int ncred, void *cbdata)
{
    for (int i = 0; i < ncred; ++i) {
        if (cred[i].type == VIR_CRED_AUTHNAME) {
            QUrl *url = static_cast<QUrl*>(cbdata);

            const QByteArray user = url->userName().toUtf8();
            if (user.isEmpty()) {
                return -1;
            }

            cred[i].result = strdup(user.constData());
            if (cred[i].result == NULL) {
                return -1;
            }
            cred[i].resultlen = user.length();
        } else if (cred[i].type == VIR_CRED_PASSPHRASE) {
            QUrl *url = static_cast<QUrl*>(cbdata);

            const QByteArray password = url->password().toUtf8();
            if (password.isEmpty()) {
                return -1;
            }

            cred[i].result = strdup(password.constData());
            if (cred[i].result == NULL) {
                return -1;
            }
            cred[i].resultlen = password.length();
        }
    }

    return 0;
}

Connection::Connection(virConnectPtr conn, QObject *parent) : QObject(parent), m_conn(conn)
{
    if (conn != NULL) virConnectRef(conn);
    virSetErrorFunc(NULL,SaveErrorFunc);
    GetSysInfo();
}



Connection::Connection(const QUrl &url, const QString &name, QObject *parent) : QObject(parent)
{
    setName(name);

    const QString uri = url.toString(QUrl::RemovePassword);
    qCDebug(VIRT_CONN) << "Connecting to" << uri;
    QUrl localUrl(url);
    virConnectAuth auth;
    auth.credtype = authCreds;
    auth.ncredtype = sizeof(authCreds)/sizeof(int);
    auth.cb = authCb;
    auth.cbdata = &localUrl;

    m_conn = virConnectOpenAuth(uri.toUtf8().constData(), &auth, 0);
    if (m_conn == NULL) {
        qCWarning(VIRT_CONN) << "Failed to open connection to" << url;
        return;
    }

    qCDebug(VIRT_CONN) << "Connected to" << uri;
}

Connection::~Connection()
{
    if (m_conn) {
        virConnectClose(m_conn);
    }
}

void Connection::SaveErrorFunc(void *userdata, virErrorPtr err)
{
/*
  fprintf(stderr, "Failure of libvirt library call:\n");
  fprintf(stderr, " Code: %d\n", err->code);
  fprintf(stderr, " Domain: %d\n", err->domain);
  fprintf(stderr, " Message: %s\n", err->message);
  fprintf(stderr, " Level: %d\n", err->level);
  fprintf(stderr, " str1: %s\n", err->str1);
  fprintf(stderr, " str2: %s\n", err->str2);
  fprintf(stderr, " str3: %s\n", err->str3);
  fprintf(stderr, " int1: %d\n", err->int1);
  fprintf(stderr, " int2: %d\n", err->int2);
*/

 // skip error: Requested operation is not valid: cgroup CPUACCT controller is not mounted 
  if ( err->code == VIR_ERR_NO_DOMAIN_METADATA) return;
   std::string str = err->message;
qDebug() <<  err->code << err->message;   
   if (str.find("cgroup CPUACCT controller is not mounted") != std::string::npos)
     return;
  m_libvirterr.append(QStringLiteral("An error ('%1') occured: '%2'").arg(err->code).arg(err->message).remove(QRegularExpression("[\\n\\t\\r]")));

}

void Connection::delErrors()
{
  virErrorPtr err;
  m_libvirterr.clear();
  err = virSaveLastError();
  virFreeError(err);

}

QString Connection::name() const
{
    return m_connName;
}


QStringList Connection::getErrors()
{
    //return m_libvirterr;
    QStringList s=m_libvirterr;
    m_libvirterr.clear();
    return s;
}




void Connection::setName(const QString &name)
{
    m_connName = name;
}

Connection *Connection::clone(QObject *parent)
{
    auto conn = new Connection(m_conn, parent);
    conn->setName(m_connName);
    return conn;
}

QString Connection::uri() const
{
    return QString::fromUtf8(virConnectGetURI(m_conn));
}

QString Connection::hostname() const
{
    QString ret;
    if (m_conn) {
        char *host = virConnectGetHostname(m_conn);
        ret = QString::fromUtf8(host);
        free(host);
    }
    return ret;
}

QString Connection::hypervisor() const
{
    return QString::fromUtf8(virConnectGetType(m_conn));
}

QString Connection::libvirt_version() const
{
    unsigned long hvVer;
    virConnectGetLibVersion(m_conn, &hvVer);

    return convert_version(hvVer);
}
QString Connection::hypervisor_version() const
{
    unsigned long hvVer;
    virConnectGetVersion(m_conn, &hvVer);

    return convert_version(hvVer);
}

QString Connection::GetSystemInfoElement(const QString &node,const QString &element) const
{
    QDomElement tmp=m_xmlsysinfo
                       .documentElement()
                       .firstChildElement(node)
                       .firstChildElement(QStringLiteral("entry"));
            
            while (!tmp.isNull()) {
                if (tmp.attribute(QStringLiteral("name")) == element)
                    return tmp.firstChild().nodeValue();
                tmp = tmp.nextSiblingElement(QStringLiteral("entry"));
            }
      return NULL;
}

QString Connection::hardware_vendor()
{
    if (!m_sysinfoLoaded) {
        GetSysInfo();
    }

   return GetSystemInfoElement("system","manufacturer");
}

QString Connection::hardware_product()
{
    if (!m_sysinfoLoaded) {
        GetSysInfo();
    }

    return GetSystemInfoElement("system","product");
}

QString Connection::hardware_serial()
{
    if (!m_sysinfoLoaded) {
        GetSysInfo();
    }

    return GetSystemInfoElement("system","serial");
}

QString Connection::bios_vendor()
{
    if (!m_sysinfoLoaded) {
        GetSysInfo();
    }

    return GetSystemInfoElement("bios","vendor");
}


QString Connection::bios_version()
{
    if (!m_sysinfoLoaded) {
        GetSysInfo();
    }

    return GetSystemInfoElement("bios","version");
}


QString Connection::bios_date()
{
    if (!m_sysinfoLoaded) {
        GetSysInfo();
    }

    return GetSystemInfoElement("bios","date");
}

QString Connection::bios_release()
{
    if (!m_sysinfoLoaded) {
        GetSysInfo();
    }

    return GetSystemInfoElement("bios","release");
}

bool Connection::GetSysInfo() 
{
     char *xml=virConnectGetSysinfo(m_conn,0);

    m_sysinfoLoaded=false;
    if (!xml) {
        qCWarning(VIRT_CONN) << "Failed to load system informations";
        return false;
    }
    const QString xmlString = QString::fromUtf8(xml);
    free(xml);

    QString errorString;
    if (!m_xmlsysinfo.setContent(xmlString, &errorString)) {
        qCCritical(VIRT_CONN) << "error" <<m_xmlsysinfo.isNull() << m_xmlsysinfo.toString();
        return false;
    }
   m_sysinfoLoaded=true;
   return true;

}


quint64 Connection::freeMemoryBytes() const
{
    if (m_conn) {
        return virNodeGetFreeMemory(m_conn);
    }
    return 0;
}

quint64 Connection::usedMemoryKiB()
{
    quint64 free = freeMemoryBytes();
    if (free) {
        return memory() - (free / 1024);
    }
    return memory();
}

quint64 Connection::memory()
{
    if (!m_nodeInfoLoaded) {
        loadNodeInfo();
    }
    return m_nodeInfo.memory;
}

QString Connection::memoryPretty()
{
    if (!m_nodeInfoLoaded) {
        loadNodeInfo();
    }
    return Virtlyst::prettyKibiBytes(m_nodeInfo.memory);
}


QString Connection::usedMemoryPretty()
{
    if (!m_nodeInfoLoaded) {
        loadNodeInfo();
    }


    return Virtlyst::prettyKibiBytes(usedMemoryKiB());
}

QString Connection::freeMemoryPretty()
{
    if (!m_nodeInfoLoaded) {
        loadNodeInfo();
    }
    return Virtlyst::prettyKibiBytes(freeMemoryBytes()/1024);
}
uint Connection::cpuThreads()
{
    if (!m_nodeInfoLoaded) {
        loadNodeInfo();
    }
    return m_nodeInfo.threads;	
}

uint Connection::cpuCores()
{
    if (!m_nodeInfoLoaded) {
        loadNodeInfo();
    }
    return m_nodeInfo.cores;	
}


uint Connection::cpuSockets()
{
   if (!m_nodeInfoLoaded) {
        loadNodeInfo();
    }
    return m_nodeInfo.sockets;	
}

uint Connection::cpuNodes()
{
    if (!m_nodeInfoLoaded) {
        loadNodeInfo();
    }
    return m_nodeInfo.nodes;	
}

uint Connection::cpus()
{
    if (!m_nodeInfoLoaded) {
        loadNodeInfo();
    }
    return m_nodeInfo.cpus;
}

uint Connection::cpus_f()
{
    if (!m_nodeInfoLoaded) {
        loadNodeInfo();
    }
    return m_nodeInfo.mhz;
}


bool Connection::isAlive()
{

    if (m_conn) {
        // This is will still return true when the connection
        // closed but no request has been made
        return virConnectIsAlive(m_conn) == 1;
    }
    return false;
}

int Connection::maxVcpus() const
{
    return virConnectGetMaxVcpus(m_conn, NULL);
}

QString Connection::cpuArch()
{
    if (!m_domainCapabilitiesLoaded) {
        loadDomainCapabilities();
    }
    return  m_xmlCapsDoc
            .documentElement()
            .firstChildElement(QStringLiteral("host"))
            .firstChildElement(QStringLiteral("cpu"))
            .firstChildElement(QStringLiteral("arch"))
            .firstChild()
            .nodeValue();
}

QString Connection::cpuVendor()
{
    if (!m_domainCapabilitiesLoaded) {
        loadDomainCapabilities();
    }
    return  m_xmlCapsDoc
            .documentElement()
            .firstChildElement(QStringLiteral("host"))
            .firstChildElement(QStringLiteral("cpu"))
            .firstChildElement(QStringLiteral("vendor"))
            .firstChild()
            .nodeValue();
}

QString Connection::cpuModel()
{
    if (!m_domainCapabilitiesLoaded) {
        loadDomainCapabilities();
    }
    return  m_xmlCapsDoc
            .documentElement()
            .firstChildElement(QStringLiteral("host"))
            .firstChildElement(QStringLiteral("cpu"))
            .firstChildElement(QStringLiteral("model"))
            .firstChild()
            .nodeValue();
}

QString Connection::osType()
{
    if (!m_domainCapabilitiesLoaded) {
        loadDomainCapabilities();
    }
    return  m_xmlCapsDoc
            .documentElement()
            .firstChildElement(QStringLiteral("guest"))
            .firstChildElement(QStringLiteral("os_type"))
            .firstChild()
            .nodeValue();
}

bool Connection::kvmSupported()
{
    if (!m_domainCapabilitiesLoaded) {
        loadDomainCapabilities();
    }

    QDomElement guest = m_xmlCapsDoc
            .documentElement()
            .firstChildElement(QStringLiteral("guest"));
    while (!guest.isNull()) {
        QDomElement arch = guest.firstChildElement(QStringLiteral("arch"));
        while (!arch.isNull()) {
            QDomElement domain = arch.firstChildElement(QStringLiteral("domain"));
            while (!domain.isNull()) {
                if (domain.attribute(QStringLiteral("type")) == QLatin1String("kvm")) {
                    return true;
                }
                domain = domain.nextSiblingElement(QStringLiteral("domain"));
            }
            arch = arch.nextSiblingElement(QStringLiteral("arch"));
        }
        guest = guest.nextSiblingElement(QStringLiteral("guest"));
    }
    return false;
}

struct cpu_stats {
    quint64 user;
    quint64 sys;
    quint64 idle;
    quint64 iowait;
    quint64 util;
    bool utilization = false;
};

bool getCPUStats(virConnectPtr conn, int cpuNum, int nparams, cpu_stats &stats)
{
    virNodeCPUStats params[nparams];
    if (virNodeGetCPUStats(conn, cpuNum, params, &nparams, 0) == 0) {
        for (int i = 0; i < nparams; ++i) {
            quint64 value = params[i].value;

            if (strcmp(params[i].field, VIR_NODE_CPU_STATS_KERNEL) == 0)
                stats.sys = value;

            if (strcmp(params[i].field, VIR_NODE_CPU_STATS_USER) == 0)
                stats.user = value;

            if (strcmp(params[i].field, VIR_NODE_CPU_STATS_IDLE) == 0)
                stats.idle = value;

            if (strcmp(params[i].field, VIR_NODE_CPU_STATS_IOWAIT) == 0)
                stats.iowait = value;

            if (strcmp(params[i].field, VIR_NODE_CPU_STATS_UTILIZATION) == 0) {
                stats.util = value;
                stats.utilization = true;
            }
        }
        return true;
    }
    return false;
}

double Connection::allCpusUsage()
{

// return QRandomGenerator::global()->bounded(100);

    int nparams = 0;
    if (virNodeGetCPUStats(m_conn, VIR_NODE_CPU_STATS_ALL_CPUS, NULL, &nparams, 0) == 0 &&
            nparams != 0) {
        cpu_stats t0;
        if (!getCPUStats(m_conn, VIR_NODE_CPU_STATS_ALL_CPUS, nparams, t0)) {
            return -1;
        }

        if (t0.utilization) 
            return pround(t0.util,2);
        

        //QEventLoop loop;
        //QTimer::singleShot(1000, &loop, &QEventLoop::quit);
        //loop.exec();
	QThread::msleep(1000);

        cpu_stats t1;
        if (!getCPUStats(m_conn, VIR_NODE_CPU_STATS_ALL_CPUS, nparams, t1)) {
            return -1;
        }

        double user_time   = t1.user   - t0.user;
        double sys_time    = t1.sys    - t0.sys;
        double idle_time   = t1.idle   - t0.idle;
        double iowait_time = t1.iowait - t0.iowait;
        double total_time  = user_time + sys_time + idle_time + iowait_time;

        double usage = (user_time + sys_time) / total_time * 100;
        return pround(usage,2);
    }
    return -1;
}

double Connection::allMemUsage()
{

// return QRandomGenerator::global()->bounded(100);
	return pround((1-((double(freeMemoryBytes()/1024))/memory()))*100,2);
}


//QStringList Connection::isoMedia()
//{
//    QStringList ret;
//    const QVector<StoragePool *> storages = storagePools(VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE, this);
//    for (StoragePool *pool : storages) {
//        const QVector<StorageVol *> vols = pool->storageVols();
//        for (StorageVol *vol : vols) {
//            const QString path = vol->path();
//            if (path.endsWith(QLatin1String(".iso"),Qt::CaseInsensitive)) {
//                ret.append(path);
//            }
//        }
//    }
//    return ret;
//}
//

QVector<StorageVol *>  Connection::isoMedia()
{

    QVector<StorageVol *> images;
    const QVector<StoragePool *> pools = storagePools(VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE, this);
    for (StoragePool *pool : pools) {
        const QVector<StorageVol *> vols = pool->storageVols(0);
        for (StorageVol * vol : vols) {
             if (vol->name().toLower().endsWith(QLatin1String(".iso")) ) {
                images.append(vol);
            }
        }
    }
    return images;
}






QVector<QVariantList> Connection::getCacheModes() const
{
    static QVector<QVariantList> cacheModes = {
        {QStringLiteral("default"), QStringLiteral("Default")},
        {QStringLiteral("none"), QStringLiteral("Disabled")},
        {QStringLiteral("writethrough"), QStringLiteral("Write through")},
        {QStringLiteral("writeback"), QStringLiteral("Write back")},
        {QStringLiteral("directsync"), QStringLiteral("Direct sync")},  // since libvirt 0.9.5
        {QStringLiteral("unsafe"), QStringLiteral("Unsafe")},  // since libvirt 0.9.7
    };
    return cacheModes;
}

QString Connection::lastError()
{
    virErrorPtr err = virGetLastError();
    const QString error = QString::fromUtf8(err->message);
    return error;
}
/*
char * MetaDataLine(const char *elem)
{
        time_t rawtime;
        struct tm * timeinfo;
	static char buffer[80];

        time (&rawtime);
        timeinfo = localtime(&rawtime);
	strftime(buffer,sizeof(buffer),"%d-%m-%Y %H:%M:%S",timeinfo);
	return (const_cast<char*> (QString("<instance>\n<%1>%2</%3>\n</instance>").arg(elem).arg(buffer).arg(elem).toStdString().c_str()));
}

*/
bool Connection::domainDefineXml(const QString &xml,bool hv_relaxed,bool hv_tsc,bool uefi,bool autostart,bool update_creationTime)
{
    virDomainPtr dom = virDomainDefineXML(m_conn, xml.toUtf8().constData());
    if (dom) {
	auto d = new Domain(dom, this);
        if (update_creationTime) 
	    d->AssignMetadata("creationTime");
	  else
	    d->AssignMetadata("lastModificationTime");

        if (uefi) {
           d->setUEFI(true);
	   d->saveXml(update_creationTime);
        }   
        if (autostart) {
           d->setAutostart(true);
	   d->saveXml(update_creationTime);
        }
	free(d);
        


	virDomainFree(dom);
        return true;
    }
    return false;
}

bool Connection::createDomain(const QString &name, const QString &memory, const QString &vcpu, bool hostModel, const QString &uuid, const QVector<StorageVol *> &images, const QString &cacheMode, const QStringList &networks, const QString &new_target_bus, const QString &new_nic_type, const QString &consoleType,const QStringList &cdroms, bool hv_relaxed,bool hv_tsc,bool uefi, bool autostart,const QStringList &boot_from)
{
    int bootorder;
    QByteArray output;
    QXmlStreamWriter stream(&output);

    stream.writeStartElement(QStringLiteral("domain"));
    stream.writeAttribute(QStringLiteral("type"), kvmSupported() ? QStringLiteral("kvm") : QStringLiteral("qemu"));

    stream.writeTextElement(QStringLiteral("name"), name);
    stream.writeTextElement(QStringLiteral("uuid"), uuid);
    stream.writeTextElement(QStringLiteral("vcpu"), vcpu);

    stream.writeStartElement(QStringLiteral("memory"));
    stream.writeAttribute(QStringLiteral("unit"), QStringLiteral("MiB"));
    stream.writeCharacters(memory);
    stream.writeEndElement(); // memory

    if (hostModel) {
        stream.writeStartElement(QStringLiteral("cpu"));
        stream.writeAttribute(QStringLiteral("mode"), QStringLiteral("host-model"));
        stream.writeEndElement(); // cpu
    }

    stream.writeStartElement(QStringLiteral("os"));
    stream.writeStartElement(QStringLiteral("type"));
    stream.writeAttribute(QStringLiteral("arch"), cpuArch());
    stream.writeAttribute(QStringLiteral("machine"), "pc-q35-4.2");
    stream.writeCharacters(osType());
    stream.writeEndElement(); // type
/*
    stream.writeEmptyElement(QStringLiteral("boot"));
    stream.writeAttribute(QStringLiteral("dev"), QStringLiteral("network"));

    stream.writeEmptyElement(QStringLiteral("boot"));
    stream.writeAttribute(QStringLiteral("dev"), QStringLiteral("cdrom"));

    stream.writeEmptyElement(QStringLiteral("boot"));
    stream.writeAttribute(QStringLiteral("dev"), QStringLiteral("hd"));
*/
    stream.writeEmptyElement(QStringLiteral("bootmenu"));
    stream.writeAttribute(QStringLiteral("enable"), QStringLiteral("yes"));
    stream.writeAttribute(QStringLiteral("timeout"), QStringLiteral("5000")); // Due to satellite link
    stream.writeEndElement(); // boot menu

    stream.writeStartElement(QStringLiteral("features"));
    stream.writeEmptyElement(QStringLiteral("acpi"));
    stream.writeEmptyElement(QStringLiteral("apic"));
    stream.writeEmptyElement(QStringLiteral("pae"));
    if (hv_relaxed){
       stream.writeStartElement(QStringLiteral("hyperv"));
       stream.writeStartElement(QStringLiteral("relaxed"));
       stream.writeAttribute(QStringLiteral("state"), "on");
       stream.writeEndElement(); //relaxed
      stream.writeEndElement();//hyperv
     } 

    stream.writeEndElement(); // features

    
    stream.writeStartElement(QStringLiteral("clock"));
    stream.writeAttribute(QStringLiteral("offset"), QStringLiteral("utc"));
     if (hv_tsc){
         stream.writeStartElement(QStringLiteral("timer"));
         stream.writeAttribute(QStringLiteral("name"), "tsc");
         stream.writeAttribute(QStringLiteral("present"), "yes");
	stream.writeEndElement(); //timer 
     }
    stream.writeEndElement(); // clock

    stream.writeTextElement(QStringLiteral("on_poweroff"), QStringLiteral("destroy"));
    stream.writeTextElement(QStringLiteral("on_reboot"), QStringLiteral("restart"));
    stream.writeTextElement(QStringLiteral("on_crash"), QStringLiteral("restart")); 

    bootorder=3;
    stream.writeStartElement(QStringLiteral("devices"));
    {
	QString alph = "abcdefghijklmnopqrstuvwxyz";
	int i=0;
        for (StorageVol *vol : images) {
            const QString type = vol->type();

            stream.writeStartElement(QStringLiteral("disk"));
            stream.writeAttribute(QStringLiteral("device"), QStringLiteral("disk"));

            if (type == QLatin1String("rbd")) {
                stream.writeAttribute(QStringLiteral("type"), QStringLiteral("network"));

                stream.writeEmptyElement(QStringLiteral("driver"));
                stream.writeAttribute(QStringLiteral("name"), QStringLiteral("qemu"));
                stream.writeAttribute(QStringLiteral("type"), type);
                if (!cacheMode.isEmpty()) {
                    stream.writeAttribute(QStringLiteral("cache"), cacheMode);
                }

                stream.writeStartElement(QStringLiteral("auth"));
                stream.writeAttribute(QStringLiteral("username"), QStringLiteral("ceph_user"));
                stream.writeEmptyElement(QStringLiteral("secret"));
                stream.writeAttribute(QStringLiteral("type"), QStringLiteral("ceph"));
                stream.writeAttribute(QStringLiteral("uuid"), QStringLiteral("ceph_uuid"));
                stream.writeEndElement(); // auth

                stream.writeEmptyElement(QStringLiteral("source"));
                stream.writeAttribute(QStringLiteral("type"), QStringLiteral("rbd"));
                stream.writeAttribute(QStringLiteral("name"), vol->path());
            } else {
                stream.writeAttribute(QStringLiteral("type"), QStringLiteral("file"));

                stream.writeEmptyElement(QStringLiteral("driver"));
                stream.writeAttribute(QStringLiteral("name"), QStringLiteral("qemu"));
		if (vol->type() != "iso")
                       stream.writeAttribute(QStringLiteral("type"), vol->type());
		else
                       stream.writeAttribute(QStringLiteral("type"), "raw");

                if (!cacheMode.isEmpty()) {
                    stream.writeAttribute(QStringLiteral("cache"), cacheMode);
                }

                stream.writeEmptyElement(QStringLiteral("source"));
                stream.writeAttribute(QStringLiteral("file"), vol->path());
		//if (i==0) {
                    stream.writeEmptyElement(QStringLiteral("boot"));
                    stream.writeAttribute(QStringLiteral("order"), QStringLiteral("%1").arg(bootorder++));
		// }   
            }

            stream.writeEmptyElement(QStringLiteral("target"));
            stream.writeAttribute(QStringLiteral("bus"), new_target_bus);
            
            stream.writeAttribute(QStringLiteral("dev"), QLatin1String("vd") + alph.mid(i,1));

            stream.writeEndElement(); // disk
	    i++;
        }
	// qDebug() << networks;
        for (const QString &network : networks) {
	  if (network != ""){
            stream.writeStartElement(QStringLiteral("interface"));
            stream.writeAttribute(QStringLiteral("type"), QStringLiteral("network"));

            stream.writeEmptyElement(QStringLiteral("source"));
            stream.writeAttribute(QStringLiteral("network"), network);

           // stream.writeEmptyElement(QStringLiteral("mac"));
           // stream.writeAttribute(QStringLiteral("address"), QStringLiteral("mac"));
   

            stream.writeEmptyElement(QStringLiteral("model"));
            stream.writeAttribute(QStringLiteral("type"), new_nic_type);


            stream.writeEndElement(); // interface
	 }   
        }
        bootorder=1;
        for(int i=1; i<=2; i++)
	{
            stream.writeStartElement(QStringLiteral("disk"));
            stream.writeAttribute(QStringLiteral("type"), QStringLiteral("file"));
            stream.writeAttribute(QStringLiteral("device"), QStringLiteral("cdrom"));
            
	    stream.writeEmptyElement(QStringLiteral("driver"));
            stream.writeAttribute(QStringLiteral("name"), QStringLiteral("qemu"));
            stream.writeAttribute(QStringLiteral("type"), QStringLiteral("raw"));

            stream.writeEmptyElement(QStringLiteral("source"));
	    if (cdroms.size()>(i-1)){
                stream.writeAttribute(QStringLiteral("file"), cdroms.at(i-1));
		
		if ( cdroms.at(i-1) == boot_from.at(0))
		    stream.writeEmptyElement(QStringLiteral("boot"));
		    stream.writeAttribute(QStringLiteral("order"), QStringLiteral("%1").arg(bootorder++));
		}
            else {
	        stream.writeAttribute(QStringLiteral("file"), QStringLiteral(""));
		stream.writeEmptyElement(QStringLiteral("boot"));
		stream.writeAttribute(QStringLiteral("order"), QStringLiteral("%1").arg(bootorder++));

		}
            stream.writeEmptyElement(QStringLiteral("target"));
	    if ( i == 1 )
                 stream.writeAttribute(QStringLiteral("dev"), QStringLiteral("sdy"));
	    else	 
                 stream.writeAttribute(QStringLiteral("dev"), QStringLiteral("sdz"));
            stream.writeAttribute(QStringLiteral("bus"), QStringLiteral("sata"));

            stream.writeEmptyElement(QStringLiteral("readonly"));

            stream.writeEmptyElement(QStringLiteral("address"));
            stream.writeAttribute(QStringLiteral("type"), QStringLiteral("drive"));
            stream.writeAttribute(QStringLiteral("controller"), QStringLiteral("1"));
            stream.writeAttribute(QStringLiteral("bus"), QStringLiteral("0"));
            stream.writeAttribute(QStringLiteral("target"), QStringLiteral("0"));
	    if ( i == 1 )
                  stream.writeAttribute(QStringLiteral("unit"), QStringLiteral("0"));
	    else	  
                  stream.writeAttribute(QStringLiteral("unit"), QStringLiteral("1"));
	    
        
	    stream.writeEndElement(); // disk
        }

        stream.writeEmptyElement(QStringLiteral("input"));
        stream.writeAttribute(QStringLiteral("type"), QStringLiteral("mouse"));
        stream.writeAttribute(QStringLiteral("bus"), QStringLiteral("ps2"));

        stream.writeEmptyElement(QStringLiteral("input"));
        stream.writeAttribute(QStringLiteral("type"), QStringLiteral("tablet"));
        stream.writeAttribute(QStringLiteral("bus"), QStringLiteral("usb"));

        stream.writeStartElement(QStringLiteral("graphics"));
        stream.writeAttribute(QStringLiteral("type"), consoleType);
        stream.writeAttribute(QStringLiteral("port"), QStringLiteral("-1"));
        stream.writeAttribute(QStringLiteral("autoport"), QStringLiteral("yes"));
        // stream.writeAttribute(QStringLiteral("listen"), QStringLiteral("127.0.0.1"));
        stream.writeAttribute(QStringLiteral("listen"), QStringLiteral("0.0.0.0"));
        stream.writeAttribute(QStringLiteral("passwd"), QUuid::createUuid().toString().remove(QLatin1Char('{')).remove(QLatin1Char('}')));
        {
            stream.writeEmptyElement(QStringLiteral("listen"));
            stream.writeAttribute(QStringLiteral("type"), QStringLiteral("address"));
            // stream.writeAttribute(QStringLiteral("address"), QStringLiteral("127.0.0.1"));
            stream.writeAttribute(QStringLiteral("address"), QStringLiteral("0.0.0.0"));
        }
        stream.writeEndElement(); // graphics

        stream.writeEmptyElement(QStringLiteral("console"));
        stream.writeAttribute(QStringLiteral("type"), QStringLiteral("pty"));

        stream.writeStartElement(QStringLiteral("video"));
        {
            stream.writeEmptyElement(QStringLiteral("model"));
            // stream.writeAttribute(QStringLiteral("type"), QStringLiteral("cirrus"));
            stream.writeAttribute(QStringLiteral("type"), QStringLiteral("vga"));
        }
        stream.writeEndElement(); // video

        stream.writeEmptyElement(QStringLiteral("memballoon"));
        stream.writeAttribute(QStringLiteral("model"), QStringLiteral("virtio"));

    }
    stream.writeEndElement(); // devices

    stream.writeEndElement(); // domain
//    qDebug() << "XML output" << output.constData();
    // qCDebug(VIRT_CONN) << "XML output" << output;
    return domainDefineXml(QString::fromUtf8(output),hv_relaxed,hv_tsc,uefi,autostart,true);
}

QVector<Domain *> Connection::domains(int flags, QObject *parent)
{
    QVector<Domain *> ret;
    virDomainPtr *domains;
    int count = virConnectListAllDomains(m_conn, &domains, flags);
    if (count > 0) {
        for (int i = 0; i < count; i++) {
            auto domain = new Domain(domains[i], this, parent);
            ret.append(domain);
        }
        free(domains);
    }
    return ret;
}

Domain *Connection::getDomainByUuid(const QString &uuid, QObject *parent)
{
    virDomainPtr domain = virDomainLookupByUUIDString(m_conn, uuid.toUtf8().constData());
    if (!domain) {
        return nullptr;
    }
    auto dom = new Domain(domain, this, parent);
    return dom;
}

Domain *Connection::getDomainByName(const QString &name, QObject *parent)
{
    virDomainPtr domain = virDomainLookupByName(m_conn, name.toUtf8().constData());
    if (!domain) {
        return nullptr;
    }
    auto dom = new Domain(domain, this, parent);
    return dom;
}

QVector<Interface *> Connection::interfaces(uint flags, QObject *parent)
{
    QVector<Interface *> ret;
    virInterfacePtr *ifaces;
    int count = virConnectListAllInterfaces(m_conn, &ifaces, flags);
    if (count > 0) {
        for (int i = 0; i < count; ++i) {
            auto iface = new Interface(ifaces[i], this, parent);
            ret.append(iface);
        }
        free(ifaces);
    }
    return ret;
}

Interface *Connection::getInterface(const QString &name, QObject *parent)
{
    virInterfacePtr iface = virInterfaceLookupByName(m_conn, name.toUtf8().constData());
    if (!iface) {
        return nullptr;
    }
    return new Interface(iface, this, parent);
}

bool Connection::createInterface(const QString &name, const QString &netdev, const QString &type,
                                 const QString &startMode, int delay, bool stp,
                                 const QString &ipv4Addr, const QString &ipv4Gw, const QString &ipv4Type,
                                 const QString &ipv6Addr, const QString &ipv6Gw, const QString &ipv6Type)
{
    QByteArray output;
    QXmlStreamWriter stream(&output);

    stream.writeStartElement(QStringLiteral("interface"));
    if (!name.isEmpty()) {
        stream.writeAttribute(QStringLiteral("name"), name);
    }
    if (!type.isEmpty()) {
        stream.writeAttribute(QStringLiteral("type"), type);
    }

    stream.writeStartElement(QStringLiteral("start"));
    stream.writeAttribute(QStringLiteral("mode"), startMode);
    stream.writeEndElement(); // start

    if (ipv4Type == QLatin1String("dhcp")) {
        stream.writeStartElement(QStringLiteral("protocol"));
        stream.writeAttribute(QStringLiteral("family"), QStringLiteral("ipv4"));
        stream.writeStartElement(QStringLiteral("dhcp"));
        stream.writeEndElement(); // dhcp
        stream.writeEndElement(); // protocol
    } else if (ipv4Type == QLatin1String("static")) {
        const QString address = ipv4Addr.section(QLatin1Char('/'), 0, 0);
        const QString prefix = ipv4Addr.section(QLatin1Char('/'), -1);
        stream.writeStartElement(QStringLiteral("protocol"));
        stream.writeAttribute(QStringLiteral("family"), QStringLiteral("ipv4"));
        stream.writeStartElement(QStringLiteral("ip"));
        stream.writeAttribute(QStringLiteral("address"), address);
        stream.writeAttribute(QStringLiteral("prefix"), prefix);
        stream.writeEndElement(); // ip
        stream.writeStartElement(QStringLiteral("route"));
        stream.writeAttribute(QStringLiteral("gateway"), ipv4Gw);
        stream.writeEndElement(); // route
        stream.writeEndElement(); // protocol
    }

    if (ipv6Type == QLatin1String("dhcp")) {
        stream.writeStartElement(QStringLiteral("protocol"));
        stream.writeAttribute(QStringLiteral("family"), QStringLiteral("ipv6"));
        stream.writeStartElement(QStringLiteral("dhcp"));
        stream.writeEndElement(); // dhcp
        stream.writeEndElement(); // protocol
    } else if (ipv6Type == QLatin1String("static")) {
        const QString address = ipv6Addr.section(QLatin1Char('/'), 0, 0);
        const QString prefix = ipv6Addr.section(QLatin1Char('/'), -1);
        stream.writeStartElement(QStringLiteral("protocol"));
        stream.writeAttribute(QStringLiteral("family"), QStringLiteral("ipv6"));
        stream.writeStartElement(QStringLiteral("ip"));
        stream.writeAttribute(QStringLiteral("address"), address);
        stream.writeAttribute(QStringLiteral("prefix"), prefix);
        stream.writeEndElement(); // ip
        stream.writeStartElement(QStringLiteral("route"));
        stream.writeAttribute(QStringLiteral("gateway"), ipv6Gw);
        stream.writeEndElement(); // route
        stream.writeEndElement(); // protocol
    }

    if (type == QLatin1String("bridge")) {
        stream.writeStartElement(QStringLiteral("bridge"));
        if (stp) {
            stream.writeAttribute(QStringLiteral("stp"), QStringLiteral("on"));
        }
        stream.writeAttribute(QStringLiteral("delay"), QString::number(delay));
        stream.writeStartElement(QStringLiteral("interface"));
        stream.writeAttribute(QStringLiteral("name"), netdev);
        stream.writeAttribute(QStringLiteral("type"), QStringLiteral("ethernet"));
        stream.writeEndElement(); // interface
        stream.writeEndElement(); // bridge
    }

    stream.writeEndElement(); // interface
    // qDebug() << "XML output" << output;
    // qCDebug(VIRT_CONN) << "XML output" << output;

    virInterfacePtr iface = virInterfaceDefineXML(m_conn, output.constData(), 0);
    if (iface) {
        virInterfaceFree(iface);
        return true;
    }
    return false;
}

QVector<Network *> Connection::networks(uint flags, QObject *parent)
{
    QVector<Network *> ret;
    virNetworkPtr *nets;
    int count = virConnectListAllNetworks(m_conn, &nets, flags);
    if (count > 0) {
        for (int i = 0; i < count; ++i) {
            auto net = new Network(nets[i], this, parent);
            ret.append(net);
        }
        free(nets);
    }
    return ret;
}

Network *Connection::getNetwork(const QString &name, QObject *parent)
{
    virNetworkPtr network = virNetworkLookupByName(m_conn, name.toUtf8().constData());
    if (!network) {
        return nullptr;
    }
    return new Network(network, this, parent);
}

bool Connection::createNetwork(const QString &name, const QString &forward, const QString &gateway, const QString &mask,
                               const QString &bridge, bool dhcp, bool openvswitch, bool fixed)
{
    QByteArray output;
    QXmlStreamWriter stream(&output);

    stream.writeStartElement(QStringLiteral("network"));

    stream.writeTextElement(QStringLiteral("name"), name);

    bool isForward = QStringList{ QStringLiteral("nat"), QStringLiteral("route"), QStringLiteral("bridge")}
            .contains(forward);
    if (isForward) {
        stream.writeStartElement(QStringLiteral("forward"));
        stream.writeAttribute(QStringLiteral("mode"), forward);
        stream.writeEndElement(); // forward
    }

    bool isForwardStp = QStringList{ QStringLiteral("nat"), QStringLiteral("route"), QStringLiteral("none")}
            .contains(forward);
    stream.writeStartElement(QStringLiteral("bridge"));
    if (isForwardStp) {
        stream.writeAttribute(QStringLiteral("stp"), QStringLiteral("on"));
        stream.writeAttribute(QStringLiteral("delay"), QStringLiteral("0"));
    } else if (forward == QLatin1String("bridge")) {
        stream.writeAttribute(QStringLiteral("name"), bridge);
    }
    stream.writeEndElement(); // bridge

    if (openvswitch) {
        stream.writeStartElement(QStringLiteral("virtualport"));
        stream.writeAttribute(QStringLiteral("type"), QStringLiteral("openvswitch"));
        stream.writeEndElement(); // virtualport
    }

    if (forward != QLatin1String("bridge")) {
        stream.writeStartElement(QStringLiteral("ip"));
        stream.writeAttribute(QStringLiteral("address"), gateway);
        stream.writeAttribute(QStringLiteral("netmask"), mask);
        if (dhcp) {
            stream.writeStartElement(QStringLiteral("dhcp"));
            stream.writeEndElement(); // dhcp
        }

        stream.writeEndElement(); // ip
    }

    stream.writeEndElement(); // network
    // qDebug() << "XML output" << output;
    // qCDebug(VIRT_CONN) << "XML output" << output;
    virNetworkPtr net = virNetworkDefineXML(m_conn, output.constData());
    if (net) {
        virNetworkFree(net);
        return true;
    }
    return false;
}



QVector<StoragePool *> Connection::storagePools(int flags, QObject *parent)
{
    QVector<StoragePool *> ret;
    virStoragePoolPtr *storagePools;
    int count = virConnectListAllStoragePools(m_conn, &storagePools, flags);
    if (count > 0) {
        for (int i = 0; i < count; ++i) {
            auto storagePool = new StoragePool(storagePools[i], parent);
            ret.append(storagePool);
        }
        free(storagePools);
    }
    return ret;
}

bool Connection::createStoragePool(const QString &name, const QString &type, const QString &source, const QString &target)
{
    QByteArray output;
    QXmlStreamWriter stream(&output);

    stream.writeStartElement(QStringLiteral("pool"));
    stream.writeAttribute(QStringLiteral("type"), type);
    stream.writeTextElement(QStringLiteral("name"), name);


    if (type == QLatin1String("logical")) {
        stream.writeStartElement(QStringLiteral("source"));

        stream.writeStartElement(QStringLiteral("device"));
        stream.writeAttribute(QStringLiteral("path"), source);
        stream.writeEndElement(); // device

        stream.writeTextElement(QStringLiteral("name"), name);

        stream.writeStartElement(QStringLiteral("format"));
        stream.writeAttribute(QStringLiteral("type"), QStringLiteral("lvm2"));
        stream.writeEndElement(); // format

        stream.writeEndElement(); // source


    }

    stream.writeStartElement(QStringLiteral("target"));
    if (type == QLatin1String("logical")) {
        stream.writeTextElement(QStringLiteral("path"), QLatin1String("/dev/") + name);
    } else {
        stream.writeTextElement(QStringLiteral("path"), target);
    }
    stream.writeEndElement(); // target

    stream.writeEndElement(); // pool
//    qDebug() << "XML output" << output;
//  qDebug(VIRT_CONN) << "XML output" << output;

    virStoragePoolPtr pool = virStoragePoolDefineXML(m_conn, output.constData(), 0);
    if (!pool) {
        // qDebug() << "virStoragePoolDefineXML" << output;
	//qDebug(VIRT_CONN) << "virStoragePoolDefineXML" << output;
        return false;
    }

    StoragePool storage(pool, this);
    if (type == QLatin1String("logical")) {
        storage.build(0);
    }
    storage.create(0);
    storage.setAutostart(true);

    return true;
}

bool Connection::createStoragePoolCeph(const QString &name, const QString &ceph_pool, const QString &ceph_host, const QString &ceph_user, const QString &secret_uuid)
{
    QByteArray output;
    QXmlStreamWriter stream(&output);

    stream.writeStartElement(QStringLiteral("pool"));
    stream.writeAttribute(QStringLiteral("type"), QStringLiteral("rbd"));
    stream.writeTextElement(QStringLiteral("name"), name);

    stream.writeStartElement(QStringLiteral("source"));

    stream.writeStartElement(QStringLiteral("host"));
    stream.writeAttribute(QStringLiteral("name"), ceph_host);
    stream.writeAttribute(QStringLiteral("port"), QStringLiteral("6789"));
    stream.writeEndElement(); // host

    stream.writeTextElement(QStringLiteral("name"), ceph_pool);

    stream.writeStartElement(QStringLiteral("auth"));
    stream.writeAttribute(QStringLiteral("username"), ceph_user);
    stream.writeAttribute(QStringLiteral("type"), QStringLiteral("ceph"));

    stream.writeStartElement(QStringLiteral("secret"));
    stream.writeAttribute(QStringLiteral("uuid"), secret_uuid);
    stream.writeEndElement(); // secret
    stream.writeEndElement(); // auth

    stream.writeEndElement(); // source

    stream.writeEndElement(); // pool
    // qDebug() << "XML output" << output;
    //qDebug(VIRT_CONN) << "XML output" << output;

    virStoragePoolPtr pool = virStoragePoolDefineXML(m_conn, output.constData(), 0);
    if (!pool) {
        // qDebug() << "virStoragePoolDefineXML" << output;
	// qDebug(VIRT_CONN) << "virStoragePoolDefineXML" << output;
        return false;
    }

    StoragePool storage(pool, this);
    storage.create(0);
    storage.setAutostart(true);
    return true;
}

bool Connection::createStoragePoolNetFs(const QString &name, const QString &netfs_host, const QString &source, const QString &source_format, const QString &target)
{
    QByteArray output;
    QXmlStreamWriter stream(&output);

    stream.writeStartElement(QStringLiteral("pool"));
    stream.writeAttribute(QStringLiteral("type"), QStringLiteral("netfs"));
    stream.writeTextElement(QStringLiteral("name"), name);

    stream.writeStartElement(QStringLiteral("source"));

    stream.writeStartElement(QStringLiteral("host"));
    stream.writeAttribute(QStringLiteral("name"), netfs_host);
    stream.writeEndElement(); // host

    stream.writeStartElement(QStringLiteral("dir"));
    stream.writeAttribute(QStringLiteral("path"), source);
    stream.writeEndElement(); // dir

    stream.writeStartElement(QStringLiteral("format"));
    stream.writeAttribute(QStringLiteral("type"), source_format);
    stream.writeEndElement(); // format

    stream.writeEndElement(); // source

    stream.writeStartElement(QStringLiteral("target"));
    stream.writeTextElement(QStringLiteral("path"), target);
    stream.writeEndElement(); // target

    stream.writeEndElement(); // pool
    //qDebug() << "XML output" << output;
    // qDebug(VIRT_CONN) << "XML output" << output;

    virStoragePoolPtr pool = virStoragePoolDefineXML(m_conn, output.constData(), 0);
    if (!pool) {
        // qDebug() << "virStoragePoolDefineXML" << output;
	// qDebug(VIRT_CONN) << "virStoragePoolDefineXML" << output;
        return false;
    }

    StoragePool storage(pool, this);
    storage.create(0);
    storage.setAutostart(true);
    return true;
}

StoragePool *Connection::getStoragePool(const QString &name, QObject *parent)
{

    virStoragePoolPtr pool = virStoragePoolLookupByName(m_conn, name.toUtf8().constData());
    if (!pool) {
        return nullptr;
    }
    return new StoragePool(pool, parent);
}


QVector<StorageVol *> Connection::getStorageImages(QObject *parent)
{


    QVector<StorageVol *> images;
    const QVector<StoragePool *> pools = storagePools(VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE, parent);
    for (StoragePool *pool : pools) {
        QVector<StorageVol *> vols = pool->storageVols(0);
        for (StorageVol * vol : vols) {
             if (!vol->name().toLower().endsWith(QLatin1String(".iso")) && vol->usedby() == "") {
                images.append(vol);
            }
        }
    }
    return images;
}


StorageVol *Connection::getStorageVolByPath(const QString &path, QObject *parent)
{
    virStorageVolPtr vol = virStorageVolLookupByPath(m_conn, path.toUtf8().constData());
    if (!vol) {
        return nullptr;
    }
    return new StorageVol(vol, nullptr, parent);
}

QVector<NodeDevice *> Connection::nodeDevices(uint flags, QObject *parent)
{
    QVector<NodeDevice *> ret;
    virNodeDevicePtr *nodes;
    int count = virConnectListAllNodeDevices(m_conn, &nodes, flags);
    if (count > 0) {
        for (int i = 0; i < count; ++i) {
            auto node = new NodeDevice(nodes[i], this, parent);
            ret.append(node);
        }
        free(nodes);
    }
    return ret;
}

void Connection::loadNodeInfo()
{
    m_nodeInfoLoaded = true;
    virNodeGetInfo(m_conn, &m_nodeInfo);
}



bool Connection::loadDomainCapabilities()
{
    char *xml = virConnectGetCapabilities(m_conn);
    if (!xml) {
        qCWarning(VIRT_CONN) << "Failed to load domain capabilities";
        return false;
    }
    const QString xmlString = QString::fromUtf8(xml);
//    qDebug() << "Caps" << xml;
//  qDebug(VIRT_CONN) << "Caps" << xml; 
    free(xml);

    QString errorString;
    if (!m_xmlCapsDoc.setContent(xmlString, &errorString)) {
        qCCritical(VIRT_CONN) << "error" << m_xmlCapsDoc.isNull() << m_xmlCapsDoc.toString();
        return false;
    }

    m_domainCapabilitiesLoaded = true;
    // qDebug() << "kvmSupported" << kvmSupported();
    return true;
}
/*
QString Connection::dataFromSimpleNode(const QString &element) const
{
    return m_xmlCapsDoc.
            documentElement().
            firstChildElement(element)
            .firstChild()
            .nodeValue();
}
*/
