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
#include "info.h"
#include "root.h"
#include "virtlyst.h"

#include "lib/connection.h"
#include "lib/domain.h"

#include <libvirt/libvirt.h>

#include <QNetworkCookie>

#include <QJsonArray>
#include <QJsonObject>
#include <QDebug>
#include <QJsonDocument>
#include <QTimer>
#include <QtMath>
#include <QDateTime>
#include <Cutelyst/Plugins/Authentication/authentication.h>
using namespace Cutelyst;

Info::Info(Virtlyst *parent)
    : Controller(parent)
    , m_virtlyst(parent)
{
}


void Info::events(Context *c,const QString &hostId )
{

//   auto user = Authentication::user(c);
//   user.setId(user.value("username").toString());
   static Connection *conn = m_virtlyst->connection(hostId, c);
    if (conn == nullptr) {
        qWarning() << "Host id not found or connection not active";
        c->response()->redirect(c->uriForAction(QStringLiteral("/index")));
        return;
    }
   // below two lines for enabling the CORS
   c->response()->setHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
   c->response()->setHeader("Access-Control-Allow-Origin", "*");
   c->response()->setHeader("Cache-Control", "no-cache");
   c->response()->setHeader("Content-Type", "text/event-stream");
   c->response()->setHeader("Connection", "keep-alive");
   c->response()->setHeader(QStringLiteral("Transfer-Encoding"), QStringLiteral("chunked"));
   // Below line is for the nginx proxies
   c->response()->setHeader(QStringLiteral("X-Accel-Buffering"), QStringLiteral("no"));

   
   static float curr_cpu=conn->allCpusUsage(); 
   static float curr_mem=conn->allMemUsage(); 
   static QJsonArray curr_status2=insts_status(c,hostId,conn,QString());
   static QJsonArray prev_status2=curr_status2;
   static float prev_cpu=100;
   static float prev_mem=100;
   QTimer *t1=m_virtlyst->t1;
   static quint64 id1=m_virtlyst->id1;



//   qDebug() << "New EventSource" <<  user.value("username").toString() << t1->isActive();
   connect(t1, &QTimer::timeout, c, [=]  {
             QJsonDocument tmp;
             QJsonObject data;
             QByteArray jsondata;
	     QString data_to_send=QString();
             if ((qFabs(prev_cpu-curr_cpu) >= 2) || (qFabs(prev_mem-curr_mem) >=2 )) { 
 
                 data.insert("date",QDateTime::currentDateTime().toString("yyyy-MM-ddTHH:mm:ss.sssZ"));
                 data.insert("cpu",QString::number(curr_cpu));
                 data.insert("memory",QString::number(curr_mem));
 
                 tmp.setObject(data);
                 jsondata = tmp.toJson(QJsonDocument::Compact);
                 data_to_send.append(QStringLiteral("\nevent: system_usage\ndata: %1\n").arg(QString(jsondata)).toUtf8());
                 data=QJsonObject();
                 tmp=QJsonDocument();
                 jsondata=QByteArray();
             }
             if (curr_status2 != prev_status2){
                 tmp.setArray(curr_status2);
                 jsondata = tmp.toJson(QJsonDocument::Compact) ;
		 data_to_send.append(QStringLiteral("\nevent: all_vm_status\ndata: %1\n").arg(QString(jsondata)).toUtf8());
                 tmp=QJsonDocument();
                 jsondata=QByteArray();
            }
	    
	    if (data_to_send.length()>0){
	       data_to_send.insert(0,QStringLiteral("retry: 5000\nid1:%1").arg(id1++).toUtf8());
	       data_to_send.append(QStringLiteral("\n"));
	       c->response()->write(data_to_send.toUtf8());
	       // qDebug() << "Sending:" << data_to_send;
	    }   
            prev_status2=curr_status2;
            curr_status2=insts_status(c,hostId,conn,QString());
            prev_cpu=curr_cpu;
            prev_mem=curr_mem;
            curr_cpu=conn->allCpusUsage(); 
            curr_mem=conn->allMemUsage(); 
   });
   // t1->start(8000);
   c->detachAsync();
}

void Info::insts_status_api(Context *c, const QString &hostId)
{
   Connection *conn = m_virtlyst->connection(hostId, c);
   c->response()->setJsonArrayBody(insts_status(c,hostId,conn,""));
}

QJsonArray Info::insts_status(Context *c,const QString &hostId,Connection *conn,const QString& inst)
{

    QJsonArray vms;
    const QVector<Domain *> domains = conn->domains(
                VIR_CONNECT_LIST_DOMAINS_ACTIVE | VIR_CONNECT_LIST_DOMAINS_INACTIVE, c);
    for (Domain *domain : domains) {
        if ( (inst.isEmpty()) || (inst == domain->name())) { 
             double difference = double(domain->memory()) / conn->memory();
             domain->setProperty("mem_usage", QString::number(difference * 100, 'g', 3));
             vms.append(QJsonObject{
                            {QStringLiteral("host"), hostId},
                            {QStringLiteral("uuid"), domain->uuid()},
                            {QStringLiteral("name"), domain->name()},
                            {QStringLiteral("dump"), 0},
                            {QStringLiteral("status"), domain->status()},
                            {QStringLiteral("memory"), domain->currentMemoryPretty()},
                            {QStringLiteral("vcpu"), domain->vcpu()},
                            {QStringLiteral("description"), domain->description()},
                            {QStringLiteral("autostart"), domain->autostart()},
                            {QStringLiteral("creationTime"), domain->creationTime()},
                            {QStringLiteral("lastModificationTime"), domain->lastModificationTime()},
                        });
          }
         delete(domain); 			
    }

    return(vms);
}

QStringList buildArrayFromCookie(const QString &cookie, qint64 value, int points)
{
    QStringList values = cookie.split(QLatin1Char(' '), QString::SkipEmptyParts);
    values.append(QString::number(value));

    if (values.size() > points) {
        values = values.mid(values.size() - points);
    }

    return values;
}

void Info::instusage(Context *c, const QString &hostId, const QString &name)
{
    Connection *conn = m_virtlyst->connection(hostId, c);
    if (conn == nullptr) {
        qWarning() << "Host id not found or connection not active";
        c->response()->redirect(c->uriForAction(QStringLiteral("/index")));
        return;
    }

    Domain *dom = conn->getDomainByName(name, c);
    if (!dom) {
        c->response()->setJsonObjectBody({
                                             {QStringLiteral("error"), QStringLiteral("Domain not found: no domain with matching name '%1'").arg(name)},
                                         });
        return;
    }

    int points = 1;
    QStringList timerArray = c->request()->cookie(QStringLiteral("timer")).split(QLatin1Char(' '), QString::SkipEmptyParts);
    QStringList cpuArray = c->request()->cookie(QStringLiteral("cpu")).split(QLatin1Char(' '), QString::SkipEmptyParts);

    timerArray.append(QTime::currentTime().toString());
    cpuArray.append(QString::number(dom->cpuUsage()));

    if (timerArray.size() > points) {
        timerArray = timerArray.mid(timerArray.size() - points);
    }
    if (cpuArray.size() > points) {
        cpuArray = cpuArray.mid(cpuArray.size() - points);
    }

    QJsonObject cpu {
        {
	 {QStringLiteral("labels"), QJsonArray::fromStringList(timerArray)},
         {QStringLiteral("data"), QJsonArray::fromStringList(cpuArray)}
        },
    };


    QJsonArray net;
    const QVector<std::pair<qint64, qint64> > net_usage = dom->netUsageMiBs();

    int netDev = 0;
    for (const std::pair<qint64, qint64> &rx_tx : net_usage) {
        const QString cookieRx = QLatin1String("net-rx-") + QByteArray::number(netDev);
        const QString cookieTx = QLatin1String("net-tx-") + QByteArray::number(netDev);
        const QString rx = c->request()->cookie(cookieRx);
        const QString tx = c->request()->cookie(cookieTx);
        const QStringList rxArray = buildArrayFromCookie(rx, rx_tx.first, points);
        const QStringList txArray = buildArrayFromCookie(tx, rx_tx.second, points);
        c->response()->setCookie(QNetworkCookie(cookieRx.toLatin1(), rxArray.join(QLatin1Char(' ')).toLatin1()));
        c->response()->setCookie(QNetworkCookie(cookieTx.toLatin1(), txArray.join(QLatin1Char(' ')).toLatin1()));

        QJsonObject network {
            {QStringLiteral("labels"), QJsonArray::fromStringList(timerArray)},
            {QStringLiteral("rx"), QJsonArray::fromStringList(rxArray)},
            {QStringLiteral("tx"), QJsonArray::fromStringList(txArray)}
        };

        net.append(QJsonObject{
                       {QStringLiteral("dev"), netDev++},
                       {QStringLiteral("data"), network},
                   });
    }


    QJsonArray hdd;
    const QMap<QString, std::pair<qint64, qint64> > hdd_usage = dom->hddUsageMiBs();
    auto it = hdd_usage.constBegin();
    while (it != hdd_usage.constEnd()) {
        const std::pair<qint64, qint64> &rd_wr = it.value();
        const QString cookieRd = QLatin1String("hdd-rd-") + it.key();
        const QString cookieWr = QLatin1String("hdd-wr-") + it.key();
        const QString rd = c->request()->cookie(cookieRd);
        const QString wr = c->request()->cookie(cookieWr);
        const QStringList rdArray = buildArrayFromCookie(rd, rd_wr.first, points);
        const QStringList wrArray = buildArrayFromCookie(wr, rd_wr.second, points);
        c->response()->setCookie(QNetworkCookie(cookieRd.toLatin1(), rdArray.join(QLatin1Char(' ')).toLatin1()));
        c->response()->setCookie(QNetworkCookie(cookieWr.toLatin1(), wrArray.join(QLatin1Char(' ')).toLatin1()));

        QJsonObject disks {
            {QStringLiteral("labels"), QJsonArray::fromStringList(timerArray)},
            {QStringLiteral("rd"), QJsonArray::fromStringList(rdArray)},
            {QStringLiteral("wr"), QJsonArray::fromStringList(wrArray)}
        };
        hdd.append(QJsonObject{
                     {QStringLiteral("dev"), it.key()},
                     {QStringLiteral("data"), disks},
                   });

        ++it;
    }


    c->response()->setCookie(QNetworkCookie("cpu", cpuArray.join(QLatin1Char(' ')).toLatin1()));

     c->response()->setJsonObjectBody({
                                         {QStringLiteral("cpu"), cpu},
				         {QStringLiteral("net"), net},
				         {QStringLiteral("hdd"), hdd},
                                     });
    c->response()->setCookie(QNetworkCookie("timer", timerArray.join(QLatin1Char(' ')).toLatin1()));
}

void Info::inst_status(Context *c, const QString &hostId, const QString &name)
{
    Connection *conn = m_virtlyst->connection(hostId, c);
    if (conn == nullptr) {
        qWarning() << "Host id not found or connection not active";
        c->response()->redirect(c->uriForAction(QStringLiteral("/index")));
        return;
    }

    Domain *dom = conn->getDomainByName(name, c);
    if (dom) {
        c->response()->setJsonObjectBody({
                                             {QStringLiteral("status"), dom->status()},
                                         });
    } else {
        c->response()->setJsonObjectBody({
                                             {QStringLiteral("error"), QStringLiteral("Domain not found: no domain with matching name '%1'").arg(name)},
                                         });
    }
}
