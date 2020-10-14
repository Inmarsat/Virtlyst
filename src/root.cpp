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
#include "root.h"

#include "virtlyst.h"

#include <Cutelyst/Plugins/Authentication/authentication.h>
#include <Cutelyst/Plugins/CSRFProtection/CSRFProtection>
#include <Cutelyst/Plugins/Session/session.h>
#include <Cutelyst/Plugins/StatusMessage>
#include <QRandomGenerator>
#include <QTimer>
#include <libvirt/libvirt.h>

#include <QLoggingCategory>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>


using namespace Cutelyst;

Root::Root(Virtlyst *parent) : Controller(parent)
  , m_virtlyst(parent)
{
 m_clients=0;
}

Root::~Root()
{
}

void Root::index(Context *c)
{
      if (m_virtlyst->servers(c).count() == 1 ) 
         c->response()->redirect(c->uriFor(QStringLiteral("/instances/%1").arg(m_virtlyst->servers(c)[0]->name)));
      else 
         c->response()->redirect(c->uriForAction(QStringLiteral("/server/index")));
	 
}

void Root::login(Context *c)
{
    Request *req = c->request();
    if (req->isPost()) {
        if (!CSRFProtection::checkPassed(c)) return;
        const ParamsMultiMap params = req->bodyParams();
        const QString username = params.value(QStringLiteral("username"));
        const QString password = params.value(QStringLiteral("password"));
        if (!username.isEmpty() && !password.isEmpty()) {
            // Authenticate
            if (Authentication::authenticate(c, params)) {
		//Session::changeExpires(c, 100000);
	        QDateTime timestamp;
                timestamp.setTime_t(Session::expires(c));
                qDebug() << Q_FUNC_INFO << username << "is now Logged in. Session expires at:" << timestamp.toString(Qt::SystemLocaleLongDate);
                c->res()->redirect(c->uriFor(CActionFor(QStringLiteral("index"))));
                return;
            } else {
                c->setStash(QStringLiteral("error_msg"), QStringLiteral("Invalid credencials"));
                qDebug() << Q_FUNC_INFO << username << "user or password invalid";
            }
        } else {
            qWarning() << "Empty username and password";
        }
        c->res()->setStatus(Response::Forbidden);
    }

    c->setStash(QStringLiteral("template"), QStringLiteral("login.html"));

}

void Root::logout(Context *c)
{
    qDebug() << "User logged out" << Authentication::user(c).value("username").toString();
    Authentication::logout(c);
    c->response()->redirect(c->uriFor(CActionFor(QStringLiteral("index"))));
}

void Root::defaultPage(Context *c)
{
    // qDebug() << Q_FUNC_INFO;
    c->setStash(QStringLiteral("template"), QStringLiteral("404.html"));
    c->response()->setStatus(404);
}

void Root::csrfdenied(Context *c)
{
    c->res()->setStatus(403);
    if (c->req()->xhr()) {
        c->res()->setJsonObjectBody({{QStringLiteral("error_msg"), QJsonValue(c->stash(QStringLiteral("error_msg")).toString())}});
    } else {
        c->setStash(QStringLiteral("template"),     QStringLiteral("csrfdenied.html"));
    }
}

bool Root::Auto(Context *c)
{
// qDebug() << __PRETTY_FUNCTION__<< c;
    StatusMessage::load(c);
    if (c->action() == CActionFor(QStringLiteral("login"))) {
        return true;
    }


    auto headers = c->request()->headers();
    auto auth = headers.authorizationBasicPair();
    auto username = auth.first;
    auto password = auth.second;

    if (!username.isEmpty() && !password.isEmpty()) {
        qDebug() << "Basic Auth detected!";

        // Prevent any inherited session getting expired
        Session::changeExpires(c, 7200);

        ParamsMultiMap params;
        params["username"] = username;
        params["password"] = password;

        if (!Authentication::userExists(c)) {
            if (!Authentication::authenticate(c, params)) {
                qDebug() << "Basic Auth failed!";
                return false;
            }
        }
    }
    else if (!Authentication::userExists(c)) {
        c->res()->redirect(c->uriFor(CActionFor(QStringLiteral("login"))));
        return false;
    }

    auto user = Authentication::user(c);
    user.setId(user.value("username").toString());
    c->setStash(QStringLiteral("user"), user);
    c->setStash(QStringLiteral("time_refresh"), 8000);





    m_clients++;
////    qDebug() << "m_clients" << m_clients;
    if ( m_clients == 1 ) m_virtlyst->t1->start(8000);
    connect(c, &QObject::destroyed, [=](){ 
        m_clients--;
////    	qDebug() << "QObject::destroyed" << m_clients;
        if ( m_clients == 0  ) m_virtlyst->t1->stop();
    });
    m_virtlyst->updateConnections();
    return true;
}


#include "moc_root.cpp"
