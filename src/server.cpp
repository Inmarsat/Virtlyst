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
#include "server.h"

#include "virtlyst.h"


#include <Cutelyst/Plugins/StatusMessage>
#include <Cutelyst/Plugins/Utils/Sql>

#include <QSqlQuery>
#include <QSqlError>

#include <QUuid>
#include <QLoggingCategory>

#include <regex>

Server::Server(Virtlyst *parent) : Controller(parent)
  , m_virtlyst(parent)
{

}

void Server::index(Context *c)
{
  c->setStash(QStringLiteral("template"), QStringLiteral("servers.html"));
  c->setStash(QStringLiteral("servers"), QVariant::fromValue(m_virtlyst->servers(c)));

    if (c->request()->isPost()) {
        const ParamsMultiMap params = c->request()->bodyParameters();
        if (params.contains(QStringLiteral("host_edit"))) {
            const QString hostId = params[QStringLiteral("host_id")];
            const QString name = params[QStringLiteral("name")];
            bool update = true;

            std::regex hostRegex("[0-9A-Za-z]+");
            if (!regex_match(hostId.toStdString(), hostRegex)) {
              c->setStash(QStringLiteral("form.name.errors"),
                          QStringLiteral("Host is invalid"));
              return;
            }

            std::regex nameRegex("[0-9A-Za-z.\\-_ ]+");
            if (!regex_match(name.toStdString(), nameRegex)) {
              c->setStash(QStringLiteral("error_msg"),
                          QStringLiteral("Name is invalid"));
              return;
            }

            updateName(hostId, name);
        } else if (params.contains(QStringLiteral("host_del"))) {
            const QString hostId = params[QStringLiteral("host_id")];

            deleteServer(hostId);
        }
        c->response()->redirect(c->uriFor(CActionFor(QStringLiteral("index"))));
        return;
    }
}

void Server::updateName(const QString &id, const QString &name)
{
    QSqlQuery query = CPreparedSqlQueryThreadForDB(
                QStringLiteral("UPDATE servers_compute "
                               "SET "
                               "name = :name "
                               "WHERE id = :id"),
                QStringLiteral("virtlyst"));

    query.bindValue(QStringLiteral(":id"), id);
    query.bindValue(QStringLiteral(":name"), name);
    if (!query.exec()) {
        qWarning() << "Failed to update connection" << query.lastError().databaseText();
    }
}

void Server::deleteServer(const QString &id)
{
    QSqlQuery query = CPreparedSqlQueryThreadForDB(
                QStringLiteral("DELETE FROM servers_compute WHERE id = :id"),
                QStringLiteral("virtlyst"));
    query.bindValue(QStringLiteral(":id"), id);
    if (!query.exec()) {
        qWarning() << "Failed to delete connection" << query.lastError().databaseText();
    }
}
