/*
 * Copyright (C) 2018 Daniel Nicoletti <dantti12@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "instances.h"
#include "virtlyst.h"

#include "lib/connection.h"
#include "lib/storagevol.h"
#include "lib/domain.h"
#include "lib/domainsnapshot.h"
#include "lib/storagepool.h"

#include <Cutelyst/Plugins/Authentication/authentication.h>
#include <Cutelyst/Plugins/CSRFProtection/CSRFProtection>
#include <libvirt/libvirt.h>
#include "lib/network.h"

#include <QUuid>
#include <QDebug>
#include <QProcess>

#include <regex>


#include <string>
#include <vector>
#include <sstream>
#include <iostream>

std::vector<std::string> split(std::string strToSplit, char delimeter)
{
    std::stringstream ss(strToSplit);
    std::string item;
    std::vector<std::string> splittedStrings;
    while (std::getline(ss, item, delimeter))
    {
       splittedStrings.push_back(item);
    }
    return splittedStrings;
}

using namespace Cutelyst;

QDebug operator<<(QDebug out, const std::string& str)
{
    out << QString::fromStdString(str);
    return out;
}

Instances::Instances(Virtlyst *parent)
    : Controller(parent)
    , m_virtlyst(parent)
{
}
static constexpr const char*  err_msg1="Invalid character detected";
void Instances::index(Context *c, const QString &hostId)
{
//qDebug() << __PRETTY_FUNCTION__;
// qDebug() << QDateTime::currentDateTime().toString("yyyy/MM/dd hh:mm:ss,zzz") << "Instances::index";

    Connection *conn = m_virtlyst->connection(hostId, c);
    if (conn == nullptr) {
        qWarning() << "Host id not found or connection not active";
        c->response()->redirect(c->uriForAction(QStringLiteral("/index")));
        return;
    }

    if (m_virtlyst->servers(c).count() == 1 )
         c->setStash(QStringLiteral("vesselname"), QVariant::fromValue(m_virtlyst->servers(c)[0]->vesselname));
         
    c->setStash(QStringLiteral("host"), QVariant::fromValue(conn));
    c->setStash(QStringLiteral("host_id"), hostId);



    auto user = Authentication::user(c);
    user.setId(user.value("username").toString());
    c->setStash(QStringLiteral("user"), user.value("username").toString());
    auto csrf_token = CSRFProtection::getToken(c);
    c->setStash(QStringLiteral("csrf_token"), csrf_token);


    const QVector<StoragePool *> storages = conn->storagePools(VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE, c);
    c->setStash(QStringLiteral("storages"), QVariant::fromValue(storages));
    const QVector<Network *> networks = conn->networks(0, c);
    c->setStash(QStringLiteral("networks"), QVariant::fromValue(networks));
    c->setStash(QStringLiteral("get_images"), QVariant::fromValue(conn->getStorageImages(c)));
    c->setStash(QStringLiteral("cache_modes"), QVariant::fromValue(conn->getCacheModes()));
    c->setStash(QStringLiteral("mac_auto"), "aa:aa:aa:aa:aa:aa");



//    QStringList errors;
//  QStringList messages;
    if (c->request()->isPost()) {
         if (!CSRFProtection::checkPassed(c)) return;
        const ParamsMultiMap params = c->request()->bodyParameters();
        const QString name = params.value(QStringLiteral("name"));

// qDebug() << params << name;
        errors.clear();
        messages.clear();

       if (params.contains(QStringLiteral("file_upload"))) {
            const auto uploads = c->request()->uploads();

            for (auto upload : uploads) {
                if (upload->filename().isEmpty())
                    continue;
                if (!validateName(c, upload->filename()))
                    return;
		QString storage_pool = params[QStringLiteral("storage_pool")];
		StoragePool *storage = conn->getStoragePool(storage_pool, c);    
                auto vol = storage->getVolume(upload->filename());
                if (!vol) {
                    qDebug() << "create storage volume: " << upload->filename();
                    vol = storage->createStorageVolume(upload->filename(),
                                                       QStringLiteral("raw"),
                                                       0,
                                                       0);

                }
                vol->upload(upload);
            }
       } 

       QStringList new_disks;

       if (params.contains(QStringLiteral("create_new_instance"))) {
         if (params.contains(QStringLiteral("image-control"))) {
           QStringList disks=params.values(QStringLiteral("image-control"));
	   disks.removeDuplicates();
            int i=0;
            for ( const QString &disk : disks.filter("new_disk_qaz")){
	         std::vector<std::string> splittedStrings = split(disk.toUtf8().constData(), ':');
                 std::string pool = splittedStrings[1];
	         std::string name = splittedStrings[2];
	         std::string size = splittedStrings[3];
	         std::string format = splittedStrings[4];
	         std::string meta_prealloc = splittedStrings[5];
	         std::string image_full_path = splittedStrings[6];
		 QString filename;
	         
                 int flags = 0;
	         if ((QString::fromUtf8(meta_prealloc.c_str()) == QLatin1String("true")) && (QString::fromUtf8(format.c_str()) == QLatin1String("qcow2"))) 
                        flags = VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;

                 filename=QString::fromUtf8(name.c_str())+Virtlyst::extensionByType(QString::fromUtf8(format.c_str()));

		 StoragePool *storage = conn->getStoragePool(QString::fromUtf8(pool.c_str()), c);
                 StorageVol *vol = storage->createStorageVolume(filename, QString::fromUtf8(format.c_str()), QString::fromUtf8(size.c_str()).toLongLong(), flags);
		 if (!vol) {
		     errors.append(conn->getErrors());
                     //return;
                  }
		 new_disks.append(QString::fromUtf8(image_full_path.c_str())+Virtlyst::extensionByType(QString::fromUtf8(format.c_str()))); 
	    }
	    for ( const QString &disk : disks.filter("new_disk_qaz")){
	         disks.removeAll(disk);
	    }
	    new_disks=disks+new_disks;
         }

         const QString vm_name = params[QStringLiteral("vm_name")];
         qreal memory = params[QStringLiteral("memory")].toDouble();
	 // memory=memory*1024;
         const QString vcpu = params[QStringLiteral("vcpu")];
         const bool hostModel = params.contains(QStringLiteral("host_model"));
         const QString cacheMode = params[QStringLiteral("cache_mode")];
         const QString new_target_bus = params[QStringLiteral("new_target_bus")];
         const QString new_nic_type = params[QStringLiteral("new_nic_type")];
         const QString consoleType = QStringLiteral("vnc");
         auto hostId = c->stash(QStringLiteral("host_id")).value<QString>();
         const bool hv_relaxed = params.contains(QStringLiteral("hv_relaxed"));
         const bool hv_tsc = params.contains(QStringLiteral("hv_tsc"));
         const bool uefi = params.contains(QStringLiteral("uefi"));
         const bool autostart = params.contains(QStringLiteral("autostart"));
     
         // if (!validateName(c, name, errors)) {
         //     return false;
         // }
     
         // if (!validateNumber(c, memory, errors)) {
         //     return false;
         // }
     
         // if (!validateNumber(c, vcpu, errors)) {
         //     return false;
         // }
         QStringList networks;
         if (!params.values(QStringLiteral("network-control")).isEmpty() ) {
             networks = params.values(QStringLiteral("network-control"));
	     networks.removeDuplicates();
	     }
         //else
     	 //networks = params.values(QStringLiteral("networks"));
    
         QStringList cdroms;
         if (!params.values(QStringLiteral("cdroms-control")).isEmpty() ) {
             cdroms = params.values(QStringLiteral("cdroms-control"));
	     cdroms.removeDuplicates();
	     }
         QStringList boot_from;
         if (!params.values(QStringLiteral("boot-control")).isEmpty() ) {
             boot_from = params.values(QStringLiteral("boot-control"));
	     boot_from .removeDuplicates();
	     }
         //else
     	 //networks = params.values(QStringLiteral("cdroms"));
        

         int flags = 0;
         if (params.contains(QStringLiteral("meta_prealloc"))) {
             flags = VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;
         }
     
         QVector<StorageVol *> volumes;
         for (const QString &image : new_disks) {
              StorageVol *vol = conn->getStorageVolByPath(image, c);
               if (vol) {
                     volumes << vol;
                 }
		 else
		    qDebug() << "Error in image:"<< image;
             }
         if (errors.isEmpty()) {


             const QString uuid = QUuid::createUuid().toString().remove(0, 1).remove(QLatin1Char('}'));
             if (conn->createDomain(vm_name, QString::number(memory), vcpu, hostModel, uuid,
                                    volumes, cacheMode, networks, new_target_bus,new_nic_type, consoleType,cdroms,hv_relaxed,hv_tsc,uefi,autostart,boot_from)) {
		 qDebug() << "Domain:" << vm_name << "created";		    
                 c->response()->redirect(c->uriFor(QStringLiteral("/instances"),
                                                   QStringList{ hostId, vm_name }));
                 return;
             } else {
	         qDebug() << conn->lastError(); 
                 errors.append(conn->lastError());
             }
         }

//qDebug() << errors;



	} 
         Domain *domain = conn->getDomainByName(name, c);
        if (domain) {
            if (params.contains(QStringLiteral("start"))){
	                if (!domain->start()) { 
                             errors.append(domain->getErrors());
			     // qDebug() << errors;
               }
    	    } else if (params.contains(QStringLiteral("shutdown"))){ 
                     domain->shutdown();
	    } else if (params.contains(QStringLiteral("destroy"))){
                     domain->destroy();
	    } else if (params.contains(QStringLiteral("reset"))){
                    domain->reset();
            } else if (params.contains(QStringLiteral("managedsave"))){
                domain->managedSave();
            } else if (params.contains(QStringLiteral("deletesaveimage"))){
                domain->managedSaveRemove();
            } else if (params.contains(QStringLiteral("suspend"))){
                domain->suspend();
            } else if (params.contains(QStringLiteral("resume"))){
                if (!domain->resume())
		   errors.append(domain->getErrors());
		    
           } 

           if (errors.isEmpty())
               c->response()->redirect(c->uriFor(CActionFor("index"), QStringList{ hostId }));
	    while (errors.count()>2) errors.removeLast(); // Due to a bug not display more than 1 errors   
	    c->setStash(QStringLiteral("errors"), errors);    
	}    
    }
    const QVector<Domain *> domains = conn->domains(
                VIR_CONNECT_LIST_DOMAINS_ACTIVE | VIR_CONNECT_LIST_DOMAINS_INACTIVE, c);
    c->setStash(QStringLiteral("instances"), QVariant::fromValue(domains));
    c->setStash(QStringLiteral("template"), QStringLiteral("instances.html"));
// qDebug() << QDateTime::currentDateTime().toString("yyyy/MM/dd hh:mm:ss,zzz") << "Instances::index-end";
}

void Instances::instance(Context *c, const QString &hostId, const QString &name)
{
 //   QStringList errors;
// qDebug() << QDateTime::currentDateTime().toString("yyyy/MM/dd hh:mm:ss,zzz") << "Instances::instance";
    errors.clear(); 
    messages.clear(); 
    c->setStash(QStringLiteral("template"), QStringLiteral("instance.html"));
    QMap<QString, QString>::const_iterator pos; 

    Connection *conn = m_virtlyst->connection(hostId, c);
    if (conn == nullptr) {
        qWarning() << "Host id not found or connection not active";
        c->response()->redirect(c->uriForAction(QStringLiteral("/index")));
        return;
    }
    c->setStash(QStringLiteral("host_id"), hostId);
    c->setStash(QStringLiteral("host"), QVariant::fromValue(conn));
    if (m_virtlyst->servers(c).count() == 1 )
         c->setStash(QStringLiteral("vesselname"), QVariant::fromValue(m_virtlyst->servers(c)[0]->vesselname));


    auto csrf_token = CSRFProtection::getToken(c);
    c->setStash(QStringLiteral("csrf_token"), csrf_token);

    Domain *dom = conn->getDomainByName(name, c);
    if (!dom) {
        errors.append(QStringLiteral("Domain not found: no domain with matching name '%1'").arg(name));
	 
	while (errors.count()>2) errors.removeLast(); // Due to a bug not display more than 1 errors 
        c->setStash(QStringLiteral("errors"), errors);
        return;
    }

    //c->setStash(QStringLiteral("console_types"), QStringList{QStringLiteral("vnc"), QStringLiteral("spice")});
    c->setStash(QStringLiteral("console_types"), QStringList{QStringLiteral("vnc")});
    
    if (c->request()->isPost()) {
        if (!CSRFProtection::checkPassed(c)) return;
        ParamsMultiMap params = c->request()->bodyParameters();
qDebug() << params;
        params.remove("csrfprotectiontoken");
        
        //errors.clear(); 
        //messages.clear(); 
	
        bool redir = false;
        if (params.contains(QStringLiteral("start"))) {
	    if (!dom->start()) {
	       errors.append(dom->getErrors());
	       }
            redir = true;
        } else if (params.contains(QStringLiteral("power"))) {
            const QString power = params.value(QStringLiteral("power"));
            if (power == QLatin1String("shutdown")) {
                dom->shutdown();
            } else if (power == QLatin1String("destroy")) {
                dom->destroy();
            } else if (power == QLatin1String("managedsave")) {
                dom->managedSave();
            }
            redir = true;
        } else if (params.contains(QStringLiteral("deletesaveimage"))) {
            dom->managedSaveRemove();
            redir = true;
        } else if (params.contains(QStringLiteral("suspend"))) {
            dom->suspend();
            redir = true;
        } else if (params.contains(QStringLiteral("resume"))) {
            dom->resume();
            redir = true;
        } else if (params.contains(QStringLiteral("unset_autostart"))) {
            dom->setAutostart(false);
            redir = true;
        } else if (params.contains(QStringLiteral("set_autostart"))) {
            dom->setAutostart(true);
            redir = true;
        } else if (params.contains(QStringLiteral("unset_uefi"))) {
            dom->setUEFI(false);
	    dom->saveXml();
            redir = true;
        } else if (params.contains(QStringLiteral("set_uefi"))) {
            dom->setUEFI(true);
	    dom->saveXml();
            redir = true;
        } else if (params.contains(QStringLiteral("delete"))) {
            if (dom->status() == VIR_DOMAIN_RUNNING) {
                dom->destroy();
            }

            if (params.contains(QStringLiteral("delete_disk"))) {
                const QVariantList disks = dom->disks();
                for (const QVariant &disk : disks) {
                    const QHash<QString, QString> diskHash = disk.value<QHash<QString, QString>>();
                    StorageVol *vol = conn->getStorageVolByPath(diskHash.value(QStringLiteral("path")), c);
                    if (vol) {
                        vol->undefine();
                    }
                }
            }
            dom->undefine();

            c->response()->redirect(c->uriFor(CActionFor("index"), QStringList{ hostId }));
            return;
        } else if (params.contains(QStringLiteral("snapshot"))) {
            const QString name = params.value(QStringLiteral("name")).trimmed();
            if (validateNamewSpace(c, name))
                if (!dom->snapshot(name)) 
		    errors.append(dom->getErrors());
		else
		   messages.append(QStringLiteral("Snapshot '%1' created successfully").arg(name));
            redir = true;
        } else if (params.contains(QStringLiteral("revert_snapshot"))) {
            const QString name = params.value(QStringLiteral("name")).trimmed();
            if (validateNamewSpace(c, name)) {
                DomainSnapshot *snap = dom->getSnapshot(name);
                if (snap) 
                    if (!snap->revert())
		       errors.append(dom->getErrors());
		    else
		       messages.append(QStringLiteral("Snapshot '%1' reverted").arg(name));
            }
            redir = true;
        } else if (params.contains(QStringLiteral("delete_snapshot"))) {
            const QString name = params.value(QStringLiteral("name")).trimmed();
            if (validateNamewSpace(c, name)) {
                DomainSnapshot *snap = dom->getSnapshot(name);
                if (snap) 
                    if (snap->undefine())
		          errors.append(dom->getErrors());
                    else
		          messages.append(QStringLiteral("Snapshot '%1' deleted").arg(name));
            }
            redir = true;
        } else if (params.contains(QStringLiteral("set_console_passwd"))) {
            QString password;
            if (params.contains(QStringLiteral("auto_pass"))) {
                password = QString::fromLatin1(QUuid::createUuid().toRfc4122().toHex());
            } else {
                password = params.value(QStringLiteral("console_passwd"));
                bool clear = params.contains(QStringLiteral("clear_pass"));
                if (clear) {
                    password.clear();
                }
                if (password.isEmpty() && !clear) {
                    errors.append(QStringLiteral("Enter the console password or select Generate"));
                }
            }

            if (errors.isEmpty()) {
                dom->setConsolePassword(password);
                dom->saveXml();
            }
            redir = true;
        } else if (params.contains(QStringLiteral("set_console_keymap"))) {
            const QString keymap = params.value(QStringLiteral("console_keymap"));
            const bool clear = params.contains(QStringLiteral("clear_keymap"));
            if (clear) {
                dom->setConsoleKeymap(QString());
            } else {
                dom->setConsoleKeymap(keymap);
            }
            dom->saveXml();
            redir = true;
        } else if (params.contains(QStringLiteral("set_console_type"))) {
            const QString type = params.value(QStringLiteral("console_type"));
            dom->setConsoleType(type);
            dom->saveXml();
            redir = true;
        } else if (params.contains(QStringLiteral("mount_iso"))) {
            const QString dev = params.value(QStringLiteral("mount_iso"));
            QString image;
            
            if (params.contains(QStringLiteral("path")))
	        image=params.value(QStringLiteral("media"));
	    else {
                 pos=params.constFind("media");
                 if (dev == "sdz")
	          image = pos.value();
	         else 
	          image = (++pos).value(); 
	      } 
            pos=params.constFind(dev);
	    QString bootfrom;
	    if (pos != params.constEnd()) 
	        bootfrom = pos.value();
            if ( !dom->mountIso(dev, image,bootfrom)) {
	         errors.append(dom->getErrors());
	         }
            redir = true;

        } else if (params.contains(QStringLiteral("umount_iso"))) {
	    const QString dev = params.value(QStringLiteral("umount_iso"));
            QString image ;


            if (params.contains(QStringLiteral("media")))
                image=params.value(QStringLiteral("path"));
            else {
                 pos=params.constFind("path");
		 if (pos == params.constEnd()) return;
                 if (dev == "sdz")
                  image = pos.value();
                 else
                  image = (++pos).value();
              }

            dom->umountIso(dev, image);
            redir = true;
        } else if (params.contains(QStringLiteral("change_settings"))) {
            bool commit = true;
            const QString description = params.value(QStringLiteral("description"));
            if (!validateNamewSpace(c, description) && !description.trimmed().isEmpty() ) 
                commit = false;
            ulong memory;
            const QString memory_custom = params.value(QStringLiteral("memory_custom"));
            if (memory_custom.isEmpty()) {
                memory = params.value(QStringLiteral("memory")).toULong();
            } else {
                if (!validateNumber(c, memory_custom)) 
                    commit = false;
                memory = memory_custom.toULong();
            }

            ulong cur_memory;
            const QString cur_memory_custom = params.value(QStringLiteral("cur_memory_custom"));
            if (memory_custom.isEmpty()) {
                cur_memory = params.value(QStringLiteral("cur_memory")).toULong();
            } else {
                if (!validateNumber(c, cur_memory_custom)) 
                    commit = false;
                cur_memory = cur_memory_custom.toULong();
            }

            if (!validateNumber(c, params.value(QStringLiteral("vcpu")))) 
                commit = false;
            if (!validateNumber(c, params.value(QStringLiteral("cur_vcpu")))) 
                commit = false;

            uint vcpu = params.value(QStringLiteral("vcpu")).toUInt();
            uint cur_vcpu = params.value(QStringLiteral("cur_vcpu")).toUInt();

            if (vcpu < cur_vcpu) {
                cur_vcpu = vcpu;
            }

            if (commit) {
                dom->setDescription(description);
                dom->setMemory(memory * 1024);
                dom->setCurrentMemory(cur_memory * 1024);
                dom->setVcpu(vcpu);
                dom->setCurrentVcpu(cur_vcpu);
                if (!dom->saveXml())
                      errors.append(dom->getErrors());
            }
            redir = true;
        }
         else 
	    if (params.contains(QStringLiteral("change_net"))) {
	   	 QStringList network_macs; 
	   	 QStringList network_types; 
	   	 QStringList network_source; 

           	 if (!params.values(QStringLiteral("network_mac")).isEmpty() )
           	     network_macs = params.values(QStringLiteral("network_mac")); 
           	 if (!params.values(QStringLiteral("network_type")).isEmpty() )
           	     network_types = params.values(QStringLiteral("network_type")); 
           	 if (!params.values(QStringLiteral("network_source")).isEmpty() )
           	     network_source = params.values(QStringLiteral("network_source")); 

           	 int i=0;
	   	 for ( const QString &network_mac : network_macs){
           	     dom->setNetworkTypeForMac(network_mac,network_types[i],network_source[i]);
	   	     i++;
	   	     }
           	 dom->saveXml();
           	 redir = true;
	 }
	 else
	    if (params.contains(QStringLiteral("change_disk"))) {
	    	QStringList disk_busses; 
	    	QStringList disk_devs; 
	    	QStringList disk_source; 
                QString disk_boot_from;

            	if (!params.values(QStringLiteral("disk_dev")).isEmpty() )
            	    disk_devs = params.values(QStringLiteral("disk_dev")); 
            	if (!params.values(QStringLiteral("disk_bus")).isEmpty() )
            	    disk_busses = params.values(QStringLiteral("disk_bus")); 
            	if (!params.values(QStringLiteral("disk_source")).isEmpty() )
            	    disk_source = params.values(QStringLiteral("disk_source")); 

            	int i=0;
	    	for ( const QString &disk_dev : disk_devs){
            	  if (!params.values(QStringLiteral("boot_from_%1").arg(disk_dev)).isEmpty() )
            	      disk_boot_from = params.values(QStringLiteral("boot_from_%1").arg(disk_dev))[0]; 
		  else
		      disk_boot_from="off";
            	      dom->setDiskDevForBus(disk_dev,disk_busses[i],disk_source[i],disk_boot_from);
	    	    i++;
	    	    }
            	dom->saveXml();
		errors.append(dom->getErrors());
            	redir = true;
	 }
	 else
            if (params.contains(QStringLiteral("remove_disk"))) {
	       QStringList disk_dev = params.values(QStringLiteral("remove_disk")); 
	       dom->RemoveDisk(disk_dev[0]);
	       if (dom->saveXml())
	           messages.append(QStringLiteral("Disk '%1' removed").arg(disk_dev[0]));
	       else 
	           errors.append(dom->getErrors());
	    }
	 else
            if (params.contains(QStringLiteral("insert_disk"))) {
	       QStringList disk_source;
	       QStringList new_target_bus;
	       QString disk_type;

               if (!params.values(QStringLiteral("disk_source_add")).isEmpty() )
                    disk_source = params.values(QStringLiteral("disk_source_add"));
               if (!params.values(QStringLiteral("new_target_bus")).isEmpty() )
                    new_target_bus = params.values(QStringLiteral("new_target_bus"));
	       StorageVol *vol = conn->getStorageVolByPath(disk_source[0], c);	    
	       disk_type=vol->type();
	       if (disk_type == "iso" )
	           disk_type="raw";
	       if ( (dom->AddDisk(disk_source[0],disk_type,new_target_bus[0])) == 0){
	           messages.append(QStringLiteral("Disk '%1' added").arg(disk_source[0]));
		   dom=conn->getDomainByName(name, c); // refresh domain to include the new disk
		   }
	       else 
	           errors.append(dom->getErrors());
	    }
            if (params.contains(QStringLiteral("insert_nic"))) {
               QStringList new_target_bus;
               QStringList new_network;

               if (!params.values(QStringLiteral("new_target_bus")).isEmpty() )
                    new_target_bus = params.values(QStringLiteral("new_target_bus"));
               if (!params.values(QStringLiteral("new_network")).isEmpty() )
                    new_network = params.values(QStringLiteral("new_network"));
               if ( (dom->AddNic(new_target_bus[0],new_network[0])) == 0){
                   messages.append(QStringLiteral("Network '%1' added").arg(new_network[0]));
                   dom=conn->getDomainByName(name, c); // refresh domain to include the new disk
                   }
               else
                   errors.append(dom->getErrors());
            }
	 else
            if (params.contains(QStringLiteral("remove_nic"))) {
	       QStringList network_mac = params.values(QStringLiteral("remove_nic")); 
	       dom->RemoveNic(network_mac[0]);
	       if (dom->saveXml())
	           messages.append(QStringLiteral("Network card with the mac: '%1' removed").arg(network_mac[0]));
	       else 
	           errors.append(dom->getErrors());
	    }
          else
	     if (params.contains(QStringLiteral("clone_instance"))) {
		       Connection *conn = m_virtlyst->connection(hostId, c);
		       int status=0;
                       QProcess cloneProcess;
		       QString exec = QStringLiteral("virt-clone --connect=qemu+ssh://opuser@%1:50022/system?no_verify=1&keyfile=/root/.ssh/id_rsa_hosting  --original %2 --name %3 --auto-clone").arg(QUrl(conn->uri()).host()).arg(params.values(QStringLiteral("old-name"))[0]).arg(params.values(QStringLiteral("clone-name"))[0]);
		       qDebug() << "Executing:"<< exec;
		       cloneProcess.start(exec);
		       cloneProcess.waitForFinished();
		       QString output(cloneProcess.readAllStandardOutput());
                       messages.append(output.replace("'", "").replace("\r", "").replace("\n",""));
		       c->response()->redirect(c->uriFor(CActionFor("index"), QStringList{ hostId }));
		       return;
		       }

//        qDebug() << " dom->saveXml();" << errors;
        if (redir && errors.isEmpty()) {
            c->response()->redirect(c->uriFor(CActionFor("index"), QStringList{ hostId, name }));
            return;
        }
    }

// qDebug() << "Errors=" << errors;

    c->setStash(QStringLiteral("host_id"), hostId);
    c->setStash(QStringLiteral("host"), QVariant::fromValue(conn));

    int vcpus = conn->maxVcpus();
    QVector<int> vcpu_range;
    for (int i = 1; i <= vcpus; ++i) {
        vcpu_range << i;
    }
    c->setStash(QStringLiteral("vcpu_range"), QVariant::fromValue(vcpu_range));

    QVector<quint64> memory_range;
    uint last = 256;
    // conn.memory is in kilobytes, I guess we need to convert to kibi bytes
    while (last <= conn->memory() / 1024) {
        memory_range.append(last);
        last *= 2;
    }
    quint64 cur_memory = dom->currentMemory() / 1024;
    if (!memory_range.contains(cur_memory)) {
        memory_range.append(cur_memory);
        std::sort(memory_range.begin(), memory_range.end(),[] (int a, int b) -> int { return a < b; });
    }
    quint64 memory = dom->memory() / 1024;
    if (!memory_range.contains(memory)) {
        memory_range.append(memory);
        std::sort(memory_range.begin(), memory_range.end(),[] (int a, int b) -> int { return a < b; });
    }
    c->setStash(QStringLiteral("memory_range"), QVariant::fromValue(memory_range));

    c->setStash(QStringLiteral("vcpu_host"), conn->cpus());
    c->setStash(QStringLiteral("memory_host"), conn->freeMemoryBytes());
    c->setStash(QStringLiteral("keymaps"), Virtlyst::keymaps());

    c->setStash(QStringLiteral("domain"), QVariant::fromValue(dom));
    const QVector<Network *> networks = conn->networks(0, c);
    c->setStash(QStringLiteral("networks"), QVariant::fromValue(networks));

    c->setStash(QStringLiteral("get_images"), QVariant::fromValue(conn->getStorageImages(c)));
    
    while (errors.count()>2) errors.removeLast(); // Due to a bug not display more than 1 errors
    c->setStash(QStringLiteral("errors"), errors);
    c->setStash(QStringLiteral("messages"), messages);

    auto user = Authentication::user(c);
    user.setId(user.value("username").toString());
    c->setStash(QStringLiteral("user"), user.value("username").toString());

//  qDebug() << "Errors=" << errors;
// qDebug() << QDateTime::currentDateTime().toString("yyyy/MM/dd hh:mm:ss,zzz") << "Instances::instance-end";
}

bool Instances::validateNumber(Context *c, const QString &input) {
    std::regex expr("[0-9]+");
    if (!std::regex_match(input.toStdString(), expr)) {
        errors.append(err_msg1);
        return false;
    }
    return true;
}

bool Instances::validateName(Context *c, const QString &input) {
    std::regex expr("[a-zA-Z0-9_\\-.]+");
    if (!std::regex_match(input.toStdString(), expr)) {
        errors.append(err_msg1);
        return false;
    }
    return true;
}

bool Instances::validateNamewSpace(Context *c, const QString &input) {
    std::regex expr("[ a-zA-Z0-9_\\-.]+");
    if (!std::regex_match(input.toStdString(), expr)) {
        errors.append(err_msg1);
        errors.append(input);
        return false;
    }
    return true;
}
