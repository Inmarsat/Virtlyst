/*
 * Copyright (C) 2020 Inmarsat
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
#include "auth.h"
#include "virtlyst.h"

#include <QLoggingCategory>
#include <Cutelyst/Plugins/Authentication/authentication.h>

Auth::Auth(Virtlyst *parent) : Controller(parent)
  ,m_virtlyst(parent)
{
}

void Auth::auth(Context *c)
{
}

void Auth::auth_GET(Context *c)
{
    qDebug() << Q_FUNC_INFO;
    c->response()->body() = "{}";
    c->response()->setStatus(Authentication::userExists(c)
                             ? Response::OK
                             : Response::Unauthorized);
}
