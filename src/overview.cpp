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
#include "overview.h"

#include "lib/connection.h"
#include "virtlyst.h"

//#include "storages.h"

#include "lib/storagepool.h"
#include <Cutelyst/Plugins/Authentication/authentication.h>

#include <QLoggingCategory>

Overview::Overview(Virtlyst *parent) : Controller(parent)
  , m_virtlyst(parent)
{

}

void Overview::index(Context *c, const QString &hostId)
{
qDebug() << __PRETTY_FUNCTION__;
    if (m_virtlyst->servers(c).count() == 1 )
         c->setStash(QStringLiteral("vesselname"), QVariant::fromValue(m_virtlyst->servers(c)[0]->vesselname));

    c->setStash(QStringLiteral("template"), QStringLiteral("hostdetail.html"));
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

    const QVector<StoragePool *> storages = conn->storagePools(0, c);
    c->setStash(QStringLiteral("storages"), QVariant::fromValue(storages));

}
