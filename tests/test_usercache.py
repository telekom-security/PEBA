import pytest
import datetime
from usercache import cacheSaveUser, cacheGetUserToken, cacheClear, cacheInvalidation

@pytest.fixture(scope="session", autouse=True)
def clearCache():
    cacheClear()

def test_saveUser():
    from usercache import users
    cacheSaveUser("testUser1", "abcd")
    cacheSaveUser("testUser2", "abcd")
    cacheSaveUser("testUser3", "abcd")
    assert len(users) == 3

def test_loadUser():
    cacheClear()
    cacheSaveUser("testUser4", "defg")
    assert cacheGetUserToken("testUser4") == "defg"

def test_loadUserNonExistent():
    cacheClear()
    with pytest.raises(Exception):
        cacheGetUserToken("testUser3")

def test_invalidation():
    cacheSaveUser("bla", "blubb")
    assert not cacheInvalidation(datetime.datetime.now())

    assert cacheGetUserToken("bla") == "blubb"
    assert cacheInvalidation(datetime.datetime.now() + datetime.timedelta(hours=25))
    with pytest.raises(Exception):
        cacheGetUserToken("bla")
