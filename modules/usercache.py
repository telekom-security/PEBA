import datetime

users = {}
lifetime = datetime.datetime.now()


class UserNotFoundException(Exception):
    pass


def cacheGetUserToken(username):
    cacheInvalidation(datetime.datetime.now())

    if username not in users:
        raise UserNotFoundException()
    return users[username]


def cacheSaveUser(username, token):

    global users
    users[username] = token


def cacheClear():
    global users
    users = {}


def cacheInvalidation(now):
    global lifetime
    if lifetime < now - datetime.timedelta(hours=24):
        cacheClear()
        lifetime = now
        return True

    return False
