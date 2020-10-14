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
#ifndef CONNECTION_H
#define CONNECTION_H

#include <QObject>
#include <QDomDocument>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

class Domain;
class Interface;
class Network;
class NodeDevice;
class StoragePool;
class StorageVol;
class Connection : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString uri READ uri CONSTANT)
    Q_PROPERTY(QString name READ name CONSTANT)
    Q_PROPERTY(QString hostname READ hostname CONSTANT)
    Q_PROPERTY(QString hypervisor READ hypervisor CONSTANT)
    Q_PROPERTY(QString hypervisor_version READ hypervisor_version CONSTANT)
    Q_PROPERTY(QString libvirt_version READ libvirt_version CONSTANT)
    Q_PROPERTY(QString hardware_vendor READ hardware_vendor CONSTANT)
    Q_PROPERTY(QString hardware_product READ hardware_product CONSTANT)
    Q_PROPERTY(QString hardware_serial READ hardware_serial CONSTANT)
    Q_PROPERTY(QString bios_vendor READ bios_vendor CONSTANT)
    Q_PROPERTY(QString bios_version READ bios_version CONSTANT)
    Q_PROPERTY(QString bios_date READ bios_date CONSTANT)
    Q_PROPERTY(QString bios_release READ bios_release CONSTANT)
    Q_PROPERTY(QString memoryPretty READ memoryPretty CONSTANT)
    Q_PROPERTY(QString usedMemoryPretty READ usedMemoryPretty CONSTANT)
    Q_PROPERTY(QString freeMemoryPretty READ freeMemoryPretty CONSTANT)
    Q_PROPERTY(uint cpus READ cpus CONSTANT)
    Q_PROPERTY(uint cpus_f READ cpus_f CONSTANT)
    Q_PROPERTY(double allCpusUsage READ allCpusUsage CONSTANT)
    Q_PROPERTY(double allMemUsage READ allMemUsage CONSTANT)
    Q_PROPERTY(QString cpuArch READ cpuArch CONSTANT)
    Q_PROPERTY(QString cpuVendor READ cpuVendor CONSTANT)
    Q_PROPERTY(QString cpuModel READ cpuModel CONSTANT)
    Q_PROPERTY(uint cpuNodes READ cpuNodes CONSTANT)
    Q_PROPERTY(uint cpuSockets READ cpuSockets CONSTANT)
    Q_PROPERTY(uint cpuCores READ cpuCores CONSTANT)
    Q_PROPERTY(uint cpuThreads READ cpuThreads CONSTANT)
    Q_PROPERTY(QVector<StorageVol*> isoMedia READ isoMedia CONSTANT)
    Q_PROPERTY(QStringList getErrors READ getErrors CONSTANT)
public:
    explicit Connection(virConnectPtr conn, QObject *parent = nullptr);
    explicit Connection(const QUrl &url, const QString &name, QObject *parent = nullptr);
    ~Connection();

    QString name() const;
    void setName(const QString &name);

    Connection *clone(QObject *parent);

    QString uri() const;
    QString hostname() const;
    QString hypervisor() const;
    QString hypervisor_version() const;
    QString libvirt_version() const;
    QString hardware_vendor();
    QString hardware_serial();
    QString hardware_product();
    QString bios_vendor();
    QString bios_version();
    QString bios_date();
    QString bios_release();
    quint64 freeMemoryBytes() const;

    quint64 usedMemoryKiB();


    quint64 memory();
    QString memoryPretty();
    QString usedMemoryPretty();
    QString freeMemoryPretty();
    uint cpus();
    uint cpus_f();

    bool isAlive();
    int maxVcpus() const;

    QString cpuArch();
    QString cpuVendor();
    QString cpuModel();
    QString osType();
    QString modelCpu();

    uint cpuNodes(); 
    uint cpuSockets(); 
    uint cpuCores();
    uint cpuThreads();

    double allCpusUsage();
    double allMemUsage();
    bool kvmSupported();

    QVector<StorageVol*> isoMedia();
    QStringList getErrors();
    void delErrors();

    QVector<QVariantList> getCacheModes() const;

    QString lastError();
    bool domainDefineXml(const QString &xml,bool hv_relaxed,bool hv_tsc,bool uefi, bool autostart,bool update_creationTime = false);
    bool createDomain(const QString &name, const QString &memory, const QString &vcpu, bool hostModel,
                      const QString &uuid, const QVector<StorageVol *> &images, const QString &cacheMode,
                      const QStringList &networks, const QString &new_target_bus, const QString &new_nic_type, 
		      const QString &consoleType,const QStringList &cdroms,
		      bool hv_relaxed,bool hv_tsc,bool uefi,bool autostart,const QStringList &boot_from);

    QVector<Domain *> domains(int flags, QObject *parent = nullptr);
    Domain *getDomainByUuid(const QString &uuid, QObject *parent = nullptr);
    Domain *getDomainByName(const QString &name, QObject *parent = nullptr);

    QVector<Interface *> interfaces(uint flags, QObject *parent = nullptr);
    Interface *getInterface(const QString &name, QObject *parent = nullptr);
    bool createInterface(const QString &name, const QString &netdev, const QString &type,
                         const QString &startMode, int delay, bool stp,
                         const QString &ipv4Addr, const QString &ipv4Gw, const QString &ipv4Type,
                         const QString &ipv6Addr, const QString &ipv6Gw, const QString &ipv6Type);

    QVector<Network *> networks(uint flags, QObject *parent = nullptr);
    Network *getNetwork(const QString &name, QObject *parent = nullptr);
    bool createNetwork(const QString &name, const QString &forward, const QString &gateway, const QString &mask,
                       const QString &bridge, bool dhcp, bool openvswitch, bool fixed = false);



    QVector<StoragePool *> storagePools(int flags, QObject *parent = nullptr);
    bool createStoragePool(const QString &name, const QString &type, const QString &source, const QString &target);
    bool createStoragePoolCeph(const QString &name, const QString &ceph_pool, const QString &ceph_host, const QString &ceph_user, const QString &secret_uuid);
    bool createStoragePoolNetFs(const QString &name, const QString &netfs_host, const QString &source, const QString &source_format, const QString &target);
    StoragePool *getStoragePool(const QString &name, QObject *parent = nullptr);
    QVector<StorageVol *> getStorageImages(QObject *parent = nullptr);

    StorageVol *getStorageVolByPath(const QString &path, QObject *parent = nullptr);

    QVector<NodeDevice *> nodeDevices(uint flags, QObject *parent = nullptr);


private:
    bool GetSysInfo();
    void loadNodeInfo();
    bool loadDomainCapabilities();
    QString GetSystemInfoElement(const QString &node,const QString &element) const;
//    QString dataFromSimpleNode(const QString &element) const;

    QString m_connName;
    static void SaveErrorFunc(void*, virErrorPtr);
    virConnectPtr m_conn;
    virNodeInfo m_nodeInfo;
    QDomDocument m_xmlCapsDoc;
    QDomDocument m_xmlsysinfo;
    bool m_sysinfoLoaded = false;
    bool m_nodeInfoLoaded = false;
    bool m_domainCapabilitiesLoaded = false;
};

#endif // CONNECTION_H
