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
#include "storages.h"

#include "lib/connection.h"
#include "lib/storagepool.h"
#include "lib/storagevol.h"
#include <Cutelyst/Plugins/Authentication/authentication.h>
#include <Cutelyst/Plugins/CSRFProtection/CSRFProtection>

#include "virtlyst.h"
#include <Cutelyst/Upload>
#include <QLoggingCategory>

#include <regex>


Storages::Storages(Virtlyst *parent) : Controller(parent)
  , m_virtlyst(parent)
{

}

void Storages::index(Context *c, const QString &hostId)
{
    if (m_virtlyst->servers(c).count() == 1 )
         c->setStash(QStringLiteral("vesselname"), QVariant::fromValue(m_virtlyst->servers(c)[0]->vesselname));

    c->setStash(QStringLiteral("template"), QStringLiteral("storages.html"));
    c->setStash(QStringLiteral("host_id"), hostId);

    Connection *conn = m_virtlyst->connection(hostId, c);
    if (conn == nullptr) {
        qWarning() << "Host id not found or connection not active";
        c->response()->redirect(c->uriForAction(QStringLiteral("/index")));
        return;
    }
    c->setStash(QStringLiteral("host"), QVariant::fromValue(conn));

    const QVector<StoragePool *> storages = conn->storagePools(0, c);
    c->setStash(QStringLiteral("storages"), QVariant::fromValue(storages));

    auto user = Authentication::user(c);
    user.setId(user.value("username").toString());
    c->setStash(QStringLiteral("user"), user.value("username").toString());

}

void Storages::storage(Context *c, const QString &hostId, const QString &pool)
{
    if (m_virtlyst->servers(c).count() == 1 )
         c->setStash(QStringLiteral("vesselname"), QVariant::fromValue(m_virtlyst->servers(c)[0]->vesselname));

    c->setStash(QStringLiteral("template"), QStringLiteral("storage.html"));
    c->setStash(QStringLiteral("host_id"), hostId);

    auto user = Authentication::user(c);
    user.setId(user.value("username").toString());
    c->setStash(QStringLiteral("user"), user.value("username").toString());


    Connection *conn = m_virtlyst->connection(hostId, c);
    if (conn == nullptr) {
        qWarning() << "Host id not found or connection not active";
        c->response()->redirect(c->uriForAction(QStringLiteral("/index")));
        return;
    }
    c->setStash(QStringLiteral("host"), QVariant::fromValue(conn));
    StoragePool *storage = conn->getStoragePool(pool, c);
    if (!storage) {
        return;
    }

    auto csrf_token = CSRFProtection::getToken(c);
    c->setStash(QStringLiteral("csrf_token"), csrf_token);

    c->setStash(QStringLiteral("storage"), QVariant::fromValue(storage));
    
    QVector<StoragePool *> storages = conn->storagePools(0, c);
    c->setStash(QStringLiteral("storages"), QVariant::fromValue(storages));

    if (c->request()->isPost()) {
        if (!CSRFProtection::checkPassed(c)) return;
        const ParamsMultiMap params = c->request()->bodyParameters();
// qDebug() << params;
        if (params.contains(QStringLiteral("start"))) {
            storage->start();
        } else if (params.contains(QStringLiteral("stop"))) {
            storage->stop();
        } else if (params.contains(QStringLiteral("delete"))) {
            storage->undefine();
            c->response()->redirect(c->uriFor(CActionFor(QStringLiteral("index")),
                                              QStringList{ hostId }));
            return;
        } else if (params.contains(QStringLiteral("set_autostart"))) {
            storage->setAutostart(true);
        } else if (params.contains(QStringLiteral("unset_autostart"))) {
            storage->setAutostart(false);
        } else if (params.contains(QStringLiteral("add_volume"))) {
            QString name = params[QStringLiteral("name")];
            const QString size = params[QStringLiteral("size")];
            const QString format = params[QStringLiteral("format")];
            int flags = 0;


            if (!validateName(c, name))
                return;

            if (!validateName(c, format))
                return;

            if (!validateNumber(c, size))
                return;
            name=name + Virtlyst::extensionByType(format);

            if (params.contains(QStringLiteral("meta_prealloc")) && format == QLatin1String("qcow2")) {
                flags = VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;
            }

            StorageVol *vol = storage->createStorageVolume(name, format, size.toLongLong(), flags);
            if (!vol) {
                  c->setStash(QStringLiteral("error_msg"), conn->getErrors());
		  return;
            }
        } else if (params.contains(QStringLiteral("expand_volume"))) {
            const QString name = params[QStringLiteral("image")];
            const QString increase_by = params[QStringLiteral("increase_by")];
            StorageVol *vol = storage->getVolume(name);
            if (vol) {
                if (!vol->expandStorageVolume(increase_by.toLongLong())){
                    c->setStash(QStringLiteral("error_msg"),conn->getErrors());
		    return;
		    }
		    
            }
        } else if (params.contains(QStringLiteral("del_volume"))) {
            const QString name = params[QStringLiteral("del_volume")];
            StorageVol *vol = storage->getVolume(name);
            if (vol) {
                vol->undefine();
            }
        } else if (params.contains(QStringLiteral("file_upload"))) {
            qDebug() << params;
            const auto uploads = c->request()->uploads();

            for (auto upload : uploads) {
                if (upload->filename().isEmpty())
                    continue;
                if (!validateName(c, upload->filename()))
                    return;
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
        } else if (params.contains(QStringLiteral("cln_volume"))) {
            const QString name = params[QStringLiteral("name")];
            const QString volName = params[QStringLiteral("image")];
            const QString existing_format  = params[QStringLiteral("existing-format")];
            QString imageName;
            QString format;
            int flags = 0;

            if (!validateName(c, name))
                return;

            if (!validateName(c, volName))
                return;

	    imageName = name + "." + existing_format;	
            if (params.contains(QStringLiteral("convert"))) {
                format = params[QStringLiteral("format")];

               imageName=name+Virtlyst::extensionByType(format);

                if (!validateName(c, format))
                    return;

                if (params.contains(QStringLiteral("meta_prealloc")) && format == QLatin1String("qcow2")) {
                    flags = VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;
                }
            }

            StorageVol *vol = storage->getVolume(volName);
            if (vol) 
                if( !vol->clone(imageName, format, flags)){
		     c->setStash(QStringLiteral("error_msg"),conn->getErrors());
		     return;
		     }
            
        }
        c->response()->redirect(c->uriFor(CActionFor(QStringLiteral("storage")),
                                          QStringList{ hostId, pool }));
	// qDebug() << "hostId" << hostId << "pool" << pool;
    }
}

bool Storages::validateNumber(Context *c, const QString &input) {
    std::regex expr("[0-9]+");
    if (!std::regex_match(input.toStdString(), expr)) {
        c->setStash(QStringLiteral("error_msg"),
                    QStringLiteral("Invalid character detected %1").arg(input));
        return false;
    }
    return true;
}

bool Storages::validateName(Context *c, const QString &input) {
    std::regex expr("[a-zA-Z0-9_\\-.]+");
    if (!std::regex_match(input.toStdString(), expr)) {
        c->setStash(QStringLiteral("error_msg"),
                    QStringLiteral("Invalid character detected %1").arg(input));
        return false;
    }
    return true;
}

