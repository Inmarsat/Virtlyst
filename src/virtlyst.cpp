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
#include "virtlyst.h"
#include <Cutelyst/Plugins/View/Cutelee/cuteleeview.h>
#include <Cutelyst/Plugins/Utils/Sql>
#include <Cutelyst/Plugins/StatusMessage>
#include <Cutelyst/Plugins/Session/Session>
#include <Cutelyst/Plugins/Authentication/credentialpassword.h>
#include <Cutelyst/Plugins/Authentication/credentialhttp.h>
#include <Cutelyst/Plugins/Authentication/authenticationrealm.h>
#include <Cutelyst/Plugins/CSRFProtection/CSRFProtection>
#include <Cutelyst/Engine>

#include <QFile>
#include <QMutexLocker>

#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QLoggingCategory>
#include <QUuid>
#include <QTranslator>
#include <QStandardPaths>
#include <QCoreApplication>
#include <QProcess>
#include <cutelee/engine.h>
#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <algorithm>
#include "lib/connection.h"
#include "infrastructure.h"
#include "instances.h"
#include "info.h"
#include "overview.h"
#include "storages.h"
#include "networks.h"
#include "interfaces.h"
#include "secrets.h"
#include "server.h"
#include "console.h"
#include "create.h"
#include "users.h"
#include "root.h"
#include "auth.h"
#include "ws.h"

#include "sqluserstore.h"

using namespace Cutelyst;

static QMutex mutex;

Q_LOGGING_CATEGORY(VIRTLYST, "fleetcompute")

bool Virtlyst::messageHandlerInstalled = false;
void syslogMessageOutput(QtMsgType type, const QMessageLogContext &context, const QString &msg)
{
    int prio = LOG_INFO;
    switch (type) {
    case QtDebugMsg:
        prio = LOG_DEBUG;
        break;
    case QtInfoMsg:
        prio = LOG_INFO;
        break;
    case QtWarningMsg:
        prio = LOG_WARNING;
        break;
    case QtCriticalMsg:
        prio = LOG_CRIT;
        break;
    case QtFatalMsg:
        prio = LOG_ALERT;
        break;
    }
    
    openlog(context.category, LOG_PID, LOG_USER);
    syslog(prio, "%s", qFormatLogMessage(type, context, msg).toUtf8().constData());
    closelog();

    if (prio == 0) {
        abort();
    }
}
Virtlyst::Virtlyst(QObject *parent) : Application(parent)
{
    QCoreApplication::setApplicationName(QStringLiteral("FleetCompute"));
    QCoreApplication::setOrganizationName(QStringLiteral("Inmarsat"));
    QCoreApplication::setApplicationVersion(QStringLiteral("2.0.0"));
}

Virtlyst::~Virtlyst()
{
    qDeleteAll(m_connections);
}

bool Virtlyst::init()
{

    if (!messageHandlerInstalled) {
            qSetMessagePattern(QStringLiteral("%{message}"));
            qInstallMessageHandler(syslogMessageOutput);
            qCInfo(VIRTLYST, "Logging backend: syslog");
	    messageHandlerInstalled = true;
    }

    auto sitePath = config(QStringLiteral("TemplatePath"), pathTo(QStringLiteral("root/src"))).toString();
    auto view = new CuteleeView(this);
    view->setTemplateExtension(QStringLiteral(".html"));
    view->setCache(false);
    view->setIncludePaths({sitePath});
    view->engine()->addDefaultLibrary(QStringLiteral("cutelee_i18ntags"));

 
    new Root(this);
    new Auth(this);
    new Infrastructure(this);
    new Instances(this);
    new Info(this);
    new Overview(this);
    new Networks(this);
    new Interfaces(this);
    new Secrets(this);
    new Server(this);
    new Storages(this);
    new Console(this);
    new Create(this);
    new Users(this);
    new Ws(this);

    bool production = config(QStringLiteral("production")).toBool();
    qCDebug(VIRTLYST) << "Production" << production;

    m_dbPath = config(QStringLiteral("DatabasePath"),
                      QStandardPaths::writableLocation(QStandardPaths::HomeLocation) + QLatin1String("/virtlyst.sqlite")).toString();
    qCDebug(VIRTLYST) << "Database" << m_dbPath;
    if (!QFile::exists(m_dbPath)) {
        qDebug() << "Failed to open database" << m_dbPath;
        //    if (!createDB()) {
        //        qDebug() << "Failed to create database" << m_dbPath;
        //        return false;
        //    }
        //    QSqlDatabase::removeDatabase(QStringLiteral("db"));
    }

   auto store = new SqlUserStore;

    auto password = new CredentialPassword;
    password->setPasswordField(QStringLiteral("password"));
    password->setPasswordType(CredentialPassword::Hashed);

    auto realm = new AuthenticationRealm(store, password);

    auto sess=new Session(this);
    sess->setup(this);
    defaultHeaders().setHeader(QStringLiteral("X-XSS-Protection"), QStringLiteral("1; mode=block"));
    defaultHeaders().setHeader(QStringLiteral("Server"), QStringLiteral("FleetCompute"));
    // defaultHeaders().removeHeader(QStringLiteral("X-Cutelyst"));
    auto auth = new Authentication(this);
    auth->addRealm(realm);
    auto csrfProtect = new CSRFProtection(this);
    csrfProtect->setDefaultDetachTo(QStringLiteral("/csrfdenied"));

    new StatusMessage(this);

    return true;
}

bool Virtlyst::postFork()
{
    QMutexLocker locker(&mutex);

    auto dbDriver = config(QStringLiteral("DatabaseDriver")).toString();
    auto db = QSqlDatabase::addDatabase(dbDriver);

    if (dbDriver == "QSQLITE") {
        db.setDatabaseName(m_dbPath);
    }
    else {

        auto db_ip = config(QStringLiteral("DatabaseIP")).toString();
        auto db_port = config(QStringLiteral("DatabasePort")).toInt();
        auto db_user = config(QStringLiteral("DatabaseUser")).toString();
        auto db_name = config(QStringLiteral("DatabaseName")).toString();
        auto db_pwd = config(QStringLiteral("DatabasePwd")).toString();

        qDebug() << "database endpoint from config.ini" << db_ip << ":" << db_port;

        db.setUserName(db_user.toUtf8());
        db.setPassword(db_pwd.toUtf8());
        db.setDatabaseName(db_name.toUtf8());
        db.setPort(db_port);
        db.setHostName(db_ip.toUtf8());
    }

    if (!db.open()) {
        qCWarning(VIRTLYST) << "Failed to open database" << db.lastError().databaseText();
        return false;
    }

    qCDebug(VIRTLYST) << "Database ready" << db.connectionName();

    updateConnections();

    return true;
}

QVector<ServerConn *> Virtlyst::servers(QObject *parent)
{
    QVector<ServerConn *> ret;
    auto it = m_connections.constBegin();
    while (it != m_connections.constEnd()) {
        ServerConn *conn = it.value()->clone(parent);
        ret.append(conn);
        ++it;
    }
    std::sort(ret.begin(), ret.end(), [](ServerConn *a, ServerConn *b){
        return a->vesselname.compare(b->vesselname);
    });
    return ret;
}

Connection *Virtlyst::connection(const QString &id, QObject *parent)
{
    QString host;
    int port;
    ServerConn *server = m_connections.value(id);
    if (server && server->conn && server->conn->isAlive()) {
        return server->conn->clone(parent);
    } else if (server) {
        if (server->conn) {
            delete server->conn;
        }
        const QString hostname = server->url.host();
        if (hostname.contains(':')) {
            QRegExp separator(":");
            QStringList list = hostname.split(separator);
            host = list.at(0);
            port = list.at(1).toInt();
        } else {
            host = hostname;
            port = 22;
        }
        if(server->type == ServerConn::ConnSSH) {
            // if(checkSSHconnection(host, port)){
            //         server->conn = server->isonline()
            //           ? new Connection(server->url, server->name, server)
            //           : nullptr;
            // }
            qDebug() << "Removed connection " << host << ":"<< port;
        } else {
            server->conn = server->isonline()
                ? new Connection(server->url, server->name, server)
                : nullptr;
        }
        if (server->conn && server->conn->isAlive()) {
            return server->conn->clone(parent);
        }
    }

    return nullptr;
}

QString Virtlyst::prettyKibiBytes(quint64 kibiBytes)
{
    QString ret;
    const char* suffixes[6];
    suffixes[0] = " KB";
    suffixes[1] = " MB";
    suffixes[2] = " GB";
    suffixes[3] = " TB";
    suffixes[4] = " PB";
    suffixes[5] = " EB";
    uint s = 0; // which suffix to use
    double count = kibiBytes;
    while (count >= 1024 && s < 6) {
        count /= 1024;
        s++;
    }
    ret = QString::number(count, 'g', 3) + QLatin1String(suffixes[s]);
    return ret;
}

QStringList Virtlyst::keymaps()
{
    // list taken from http://qemu.weilnetz.de/qemu-doc.html#sec_005finvocation
    static QStringList ret = {
        QStringLiteral("ar"), QStringLiteral("da"), QStringLiteral("de"),
        QStringLiteral("de-ch"), QStringLiteral("en-gb"), QStringLiteral("en-us"),
        QStringLiteral("es"), QStringLiteral("et"), QStringLiteral("fi"),
        QStringLiteral("fo"), QStringLiteral("fr"), QStringLiteral("fr-be"),
        QStringLiteral("fr-ca"), QStringLiteral("fr-ch"), QStringLiteral("hr"),
        QStringLiteral("hu"), QStringLiteral("is"), QStringLiteral("it"),
        QStringLiteral("ja"), QStringLiteral("lt"), QStringLiteral("lv"),
        QStringLiteral("mk"), QStringLiteral("nl"), QStringLiteral("nl-be"),
        QStringLiteral("no"), QStringLiteral("pl"), QStringLiteral("pt"),
        QStringLiteral("pt-br"), QStringLiteral("ru"), QStringLiteral("sl"),
        QStringLiteral("sv"), QStringLiteral("th"), QStringLiteral("tr")
    };
    return ret;
}

//bool Virtlyst::createDbFlavor(QSqlQuery &query, const QString &label, int memory, int vcpu, int disk)
//{
//    query.bindValue(QStringLiteral(":label"), label);
//    query.bindValue(QStringLiteral(":memory"), memory);
//    query.bindValue(QStringLiteral(":vcpu"), vcpu);
//    query.bindValue(QStringLiteral(":disk"), disk);
//    return query.exec();
//}

void Virtlyst::updateConnections()
{
    QSqlQuery query = CPreparedSqlQueryThreadForDB(
        QStringLiteral("SELECT id, name, vessel_name, hostname, type, customer_number, version FROM servers_compute"),
        QStringLiteral("virtlyst"));
    if (!query.exec()) {
        qCWarning(VIRTLYST) << "Failed to get connections list";
    }

    QStringList ids;
    while (query.next()) {
        const QString id = query.value(0).toString();
        const QString name = query.value(1).toString();
        const QString vessel = query.value(2).toString();
        const QString hostname = query.value(3).toString();
        int type = query.value(4).toInt();
        ids << id;
        const QString cnumber = query.value(5).toString();
        const QString version = query.value(6).toString();

        qDebug() << "id: " << id;
        qDebug() << "name: " << name;
        qDebug() << "vessel: " << vessel;
        qDebug() << "hostname: " << hostname;
        qDebug() << "cnumber: " << cnumber;
        qDebug() << "version: " << version;

        ServerConn *server;
        server = new ServerConn(this);
        server->id = id;
        server->name = name;
        server->vesselname = vessel;
        server->hostname = hostname;
        server->type = type;
        server->cnumber = cnumber;
        server->version = version;

        QUrl url;
        QString host;
        QString sshcmd;
        int port;

        url = QStringLiteral("qemu+ssh:///system?no_verify=1&keyfile=/root/.ssh/id_rsa_hosting");
        server->url = url;

        server->conn = server->isonline() ?
            new Connection(url, name, server)
            : nullptr;
        m_connections.insert(id, server);
    }

    auto it = m_connections.begin();
    while (it != m_connections.end()) {
        if (!ids.contains(it.key())) {
            it.value()->deleteLater();
            it = m_connections.erase(it);
        } else {
            ++it;
        }
    }
}


bool ServerConn::isonline()
{
    QSqlQuery query = CPreparedSqlQueryThreadForDB(
        QStringLiteral("SELECT name FROM servers_compute WHERE last_identity_update > CURRENT_TIMESTAMP - INTERVAL '7 min' AND name=:name;"),
        QStringLiteral("virtlyst"));

    query.bindValue(QStringLiteral(":name"), name);

    if (!query.exec()) {
        qWarning() << "Failed to get online status" << query.lastError().databaseText();
    }
    if( query.next() ){
        return true;
    }
    return false;
}


bool ServerConn::alive()
{
    if (conn) {
        return conn->isAlive();
    }
    return false;
}

ServerConn *ServerConn::clone(QObject *parent)
{
    auto ret = new ServerConn(parent);
    ret->id = id;
    ret->name = name;
    ret->vesselname = vesselname;
    ret->hostname = hostname;
    ret->login = login;
    ret->password = password;
    ret->cnumber = cnumber;
    ret->version = version;
    ret->type = type;
    ret->url = url;

    QString host;
    int port;
    if (hostname.contains(':')) {
        QRegExp separator(":");
        QStringList list = hostname.split(separator);
        host = list.at(0);
        port = list.at(1).toInt();
    } else {
        host = hostname;
        port = 22;
    }

    ret->conn = ret->isonline() ? conn->clone(ret) : nullptr;

    return ret;
}

bool checkSSHconnection(QString &host, int port)
{
    ssh_session my_ssh_session;
    int rc;
    bool ret;

    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL)
        exit(-1);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, host.toStdString().c_str());
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);
    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK)
        {
            qWarning() << "Error connecting to host - " << ssh_get_error(my_ssh_session);
            ret = false;
        }
    else {
        qDebug() << "ssh connection successful ";
        ret = true;
    }

    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    return ret;
}
