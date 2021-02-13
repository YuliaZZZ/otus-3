import hashlib
import datetime
import functools
import unittest

import api
from store import Store


def cases(cases):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args):
            for c in cases:
                try:
                    new_args = args + (c if isinstance(c, tuple) else (c,))
                    f(*new_args)
                except Exception:
                    raise Exception(f.__name__, c)
        return wrapper
    return decorator


class TestSuite(unittest.TestCase):
    def setUp(self):
        self.context = {}
        self.headers = {}
        self.settings = Store()  # {}

    def get_response(self, request):
        return api.method_handler({"body": request, "headers": self.headers}, self.context, self.settings)

    def set_valid_auth(self, request):
        if request.get("login") == api.ADMIN_LOGIN:
            request["token"] = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + api.ADMIN_SALT).encode()).hexdigest()
        else:
            msg = request.get("account", "") + request.get("login", "") + api.SALT
            request["token"] = hashlib.sha512(msg.encode()).hexdigest()
        return request

    def test_empty_request(self):
        _, code, context = self.get_response({})
        self.assertEqual(api.INVALID_REQUEST, code)

    @cases([
        {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "", "arguments": {}},
        {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "sdd", "arguments": {}},
        {"account": "horns&hoofs", "login": "admin", "method": "online_score", "token": "", "arguments": {}},
    ])
    def test_bad_auth(self, request):
        _, code, context = self.get_response(request)
        self.assertEqual(api.FORBIDDEN, code)

    @cases([
        {"account": "horns&hoofs", "login": "h&f", "method": "online_score"},
        {"account": "horns&hoofs", "login": "h&f", "arguments": {}},
        {"account": "horns&hoofs", "method": "online_score", "arguments": {}},
    ])
    def test_invalid_method_request(self, request):
        self.set_valid_auth(request)
        response, code, context = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code)
        self.assertTrue(response)

    @cases([
        {},
        {"phone": "79175002040"},
        {"phone": "89175002040", "email": "stupnikov@otus.ru"},
        {"phone": "79175002040", "email": "stupnikovotus.ru"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": -1},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": "1"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.1890"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "XXX"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.2000", "first_name": 1},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.2000",
         "first_name": "s", "last_name": 2},
        {"phone": "79175002040", "birthday": "01.01.2000", "first_name": "s"},
        {"email": "stupnikov@otus.ru", "gender": 1, "last_name": 2},
    ])
    def test_invalid_score_request(self, arguments):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": arguments}
        self.set_valid_auth(request)
        response, code, context = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code, arguments)
        self.assertTrue(response)

    @cases([
        {"phone": "79175002040", "email": "stupnikov@otus.ru"},
        {"phone": 79175002040, "email": "stupnikov@otus.ru"},
        {"gender": 1, "birthday": "01.01.2000", "first_name": "a", "last_name": "b"},
        {"gender": 0, "birthday": "01.01.2000"},
        {"gender": 2, "birthday": "01.01.2000"},
        {"first_name": "a", "last_name": "b"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.2000",
         "first_name": "a", "last_name": "b"},
    ])
    def test_ok_score_request(self, arguments):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": arguments}
        request = self.set_valid_auth(request)
        response, code, ctx = self.get_response(request)
        self.assertEqual(api.OK, code, arguments)
        score = response.get("score")
        self.assertTrue(isinstance(score, (int, float)) and score >= 0, arguments)
        self.assertEqual(sorted(self.context["has"]), sorted(arguments.keys()))

    def test_ok_score_admin_request(self):
        arguments = {"phone": "79175002040", "email": "stupnikov@otus.ru"}
        request = {"account": "horns&hoofs", "login": "admin", "method": "online_score", "arguments": arguments}
        self.set_valid_auth(request)
        response, code, ctx = self.get_response(request)
        self.assertEqual(api.OK, code)
        score = response.get("score")
        self.assertEqual(score, 42)

    @cases([
        {},
        {"date": "20.07.2017"},
        {"client_ids": [], "date": "20.07.2017"},
        {"client_ids": {1: 2}, "date": "20.07.2017"},
        {"client_ids": ["1", "2"], "date": "20.07.2017"},
        {"client_ids": [1, 2], "date": "XXX"},
    ])
    def test_invalid_interests_request(self, arguments):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "clients_interests", "arguments": arguments}
        self.set_valid_auth(request)
        response, code, ctx = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code, arguments)
        self.assertTrue(len(response))

    @cases([
        {"client_ids": [1, 2, 3], "date": datetime.datetime.today().strftime("%d.%m.%Y")},
        {"client_ids": [1, 2], "date": "19.07.2017"}
    ])
    def test_store_empty_intests_request(self, arguments):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "clients_interests", "arguments": arguments}
        self.set_valid_auth(request)
        response, code, ctx = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code, arguments)

    @cases([
        ["l", '06-07-1956'],
        [3, '1987.12.12'],
        [['a', 'b'], '1.09.90']
    ])
    def test_false_fields_clients_interesrs_request(self, arguments):
        clients_interests = api.ClientsInterestsRequest()
        with self.assertRaises(ValueError):
            clients_interests.client_ids = arguments[0]
        with self.assertRaises(ValueError):
            clients_interests.date = arguments[1]

    @cases([
        [(1, 2), '06.07.1956'],
        [[1, 2], '12.12.1987'],
        [[1], '01.09.1990']
    ])
    def test_ok_fields_clients_interesrs_request(self, arguments):
        clients_interests = api.ClientsInterestsRequest()
        clients_interests.client_ids = arguments[0]
        clients_interests.date = arguments[1]
        self.assertTrue(isinstance(clients_interests, api.ClientsInterestsRequest))

    @cases([
        [(1, 2), 'todo.ru', '12.12.1920', '89213333333', 'm'],
        [2, 'todo', '12.12.87', '755555', 4]
    ])
    def test_false_fields_online_score_request(self, arguments):
        online_score_request = api.OnlineScoreRequest()
        with self.assertRaises(ValueError):
            online_score_request.first_name = arguments[0]
            online_score_request.email = arguments[1]
            online_score_request.birthday = arguments[2]
            online_score_request.phone = arguments[3]
            online_score_request.gender = arguments[4]

    @cases([
        ['Tom', 'todo@do.ru', '12.12.1980', '79213333333', 1],
        ['Pol', 't@k.ru', '12.12.1987', '79213333333', 2]
    ])
    def test_ok_fields_online_score_request(self, arguments):
        online_score_request = api.OnlineScoreRequest()
        online_score_request.first_name = arguments[0]
        online_score_request.email = arguments[1]
        online_score_request.birthday = arguments[2]
        online_score_request.phone = arguments[3]
        online_score_request.gender = arguments[4]
        self.assertTrue(isinstance(online_score_request, api.OnlineScoreRequest))

    @cases([
        [(1, 2), 123, 'abc', 'lol'],
        [['a', 'b'], 'kl', 'abc', 'lol']
    ])
    def test_false_fields_method_request(self, arguments):
        method_request = api.MethodRequest()
        with self.assertRaises(ValueError):
            method_request.arguments = arguments[0]
            method_request.token = arguments[1]
            method_request.login = arguments[2]
            method_request.method = arguments[3]

    @cases([
        [{}, '', '', ''],
        [{1: 'jk'}, 'kl', 'abc', 'lol']
    ])
    def test_ok_fields_method_request(self, arguments):
        method_request = api.MethodRequest()
        method_request.arguments = arguments[0]
        method_request.token = arguments[1]
        method_request.login = arguments[2]
        method_request.method = arguments[3]
        self.assertTrue(isinstance(method_request, api.MethodRequest))


if __name__ == "__main__":
    unittest.main()
