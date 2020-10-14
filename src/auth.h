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
#ifndef AUTH_H
#define AUTH_H

#include <Cutelyst/Controller>

using namespace Cutelyst;

class Virtlyst;
class Auth : public Controller
{
    Q_OBJECT
public:
    explicit Auth(Virtlyst *parent = nullptr);
    ~Auth() {}

    C_ATTR(auth, :Path :Args(0) :ActionClass(REST))
    void auth(Context *c);

    C_ATTR(auth_GET, :Private)
    void auth_GET(Context *c);

private:

    Virtlyst *m_virtlyst;
};

#endif //AUTH_H
