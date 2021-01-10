#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from scoring import get_interests, get_score


SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class Field(abc.ABC):
    @abc.abstractmethod
    def _check(self, value):
        pass


class Value(Field):
    def __init__(self, required, nullable):
        self.label = None
        self._null = nullable
        self._req = required

    def __get__(self, obj, obj_type):
        return obj.__dict__[self.label]

    def __set__(self, obj, val):
        if self._null is False and val in [None, '', []]:
            raise ValueError(f"Поле {self.label} не может быть пустым.")
        elif self._null is True and val in [None, '']:
            obj.__dict__[self.label] = None
        else:
            obj.__dict__[self.label] = self._check(val)

    def __set_name__(self, owner, name):
        self.label = name


class CharField(Value, Field):
    def _check(self, value):
        try:
            assert isinstance(value, str)
        except AssertionError:
            raise TypeError(f'Поле {self.label} должно содержать строковое значение')
        return value


class ArgumentsField(Value, Field):
    def _check(self, value):
        try:
            assert isinstance(value, dict)
        except (AssertionError, ValueError):
            raise TypeError(f'Поле {self.label} должно быть объектом json')
        return value


class EmailField(CharField):
    def _check(self, value):
        try:
            super(CharField, self)._check(value)
            assert '@' in value
        except AssertionError:
            raise ValueError(f'Поле {self.label} должно содержать @')
        return value


class PhoneField(Value, Field):
    def _check(self, value):
        try:
            value = str(value)
            assert len(value) == 11
            assert value[0] == '7'
        except AssertionError:
            raise ValueError(f'Поле {self.label} должно содержать 11 цифр и начинаться с 7')
        return value


class DateField(Value, Field):
    def _check(self, value):
        try:
            value = datetime.datetime.strptime(value, "%d.%m.%Y")
            # value_f = value.strftime("%d.%m.%Y")
            assert isinstance(value, datetime.date)
        except (AssertionError, ValueError):
            raise ValueError(f'Поле {self.label} должно содержать дату в формате ДД.ММ.ГГГГ')
        return value


class BirthDayField(DateField):
    def _check(self, value):
        delta = datetime.datetime.now() - datetime.timedelta(days=(365 * 70))
        try:
            value = DateField._check(self, value)
            assert value >= delta
        except (AssertionError, ValueError):
            raise ValueError(f'Поле {self.label} должно содержать дату в формате ДД.ММ.ГГГГ')
        return value


class GenderField(Value, Field):
    def _check(self, value):
        try:
            assert value in list(GENDERS.keys())
        except AssertionError:
            raise ValueError(
                f'Поле {self.label} должно иметь одно из следующих значений: {list(GENDERS.keys())}')
        else:
            return value


class ClientIDsField(Value, Field):
    def _check(self, value):
        try:
            assert isinstance(value, list) or isinstance(value, tuple)
            assert list(map(lambda x: isinstance(x, int), value)) == [True for i in value]
        except AssertionError:
            raise ValueError(f'Поле {self.label} должно содержать перечень значений id')
        else:
            return value


class ClientsInterestsRequest(object):
    client_ids = ClientIDsField(required=True, nullable=False)
    date = DateField(required=False, nullable=True)

    def _check_req(self):
        pass

    @property
    def special_row(self):
        return {"nclients": len(self.client_ids)}

    def _start_method(self, store):
        return {f"client_id{i}": get_interests(store, i) for i in self.client_ids}


class OnlineScoreRequest(object):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def _check_req(self):
        if (self.first_name and self.last_name) or (
                self.phone and self.email) or (
                self.birthday and self.gender in list(GENDERS.keys())
        ):
            pass
        else:
            raise ValueError("Не валидный запрос")

    def _start_method(self, store):
        return {"score": get_score(store, self.phone, self.email, self.birthday,
                                   self.gender, self.first_name, self.last_name)}

    @property
    def special_row(self):
        return {
            "has": [key for key, value in self.__dict__.items() if value or value == 0]}


class MethodRequest(object):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=True)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN

    @staticmethod
    def update_dict(obj, kwargs, cls):
        for k, v in cls.__dict__.items():
            if k[0] != "_" and k in kwargs:
                cls.__setattr__(obj, k, kwargs[k])
            elif k[0] != "_":
                prop = cls.__dict__[k]
                property_val = None
                cls_property = prop.__class__
                if not issubclass(cls_property, staticmethod) and (not issubclass(cls_property, property)):
                    property_val = prop._req
                    if property_val:
                        raise ValueError(f"Поле {k} обязательно.")
                    else:
                        cls.__setattr__(obj, k, None)


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(
            (datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode()).hexdigest()
    else:
        digest = hashlib.sha512(
            (request.account + request.login + SALT).encode()).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    response, code, resp = None, None, None
    try:
        req = MethodRequest()
        req.account, req.token, req.login = request["body"]["account"], request["body"]["token"], \
                                            request["body"]["login"]
        if check_auth(req):
            prop = request["body"]["arguments"]
            MethodRequest.update_dict(req, request["body"], req.__class__)

            if req.method == "online_score":
                resp = OnlineScoreRequest()
            elif req.method == "clients_interests":
                resp = ClientsInterestsRequest()

            MethodRequest.update_dict(resp, prop, resp.__class__)
            resp._check_req()
            ctx.update(resp.special_row)

            if req.is_admin and req.method == "online_score":
                response, code = {'score': int(ADMIN_SALT)}, OK
            else:
                response, code = resp._start_method(store), OK
        else:
            raise PermissionError
    except PermissionError:
        response, code = ERRORS[FORBIDDEN], FORBIDDEN
    except Exception as e:
        response, code = ERRORS[INVALID_REQUEST], INVALID_REQUEST
        logging.error(f"{Exception, e}")

    return response, code, ctx


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except Exception:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")

            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code, context = self.router[path]({"body": request, "headers": self.headers}, context,
                                                                self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        # r = json.loads(r)

        self.wfile.write(b'r')
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
