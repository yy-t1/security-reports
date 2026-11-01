import asyncio, sys
from mysql_mimic import MysqlServer, Session
from mysql_mimic.auth import AuthPlugin, IdentityProvider, Success, User, FILLER

class AcceptAll(AuthPlugin):
    name = "mysql_native_password"
    client_plugin_name = None
    async def auth(self, auth_info=None):
        if not auth_info:
            auth_info = yield FILLER
        yield Success(auth_info.username if auth_info else "anon")

class Provider(IdentityProvider):
    def get_plugins(self):
        return [AcceptAll()]
    async def get_user(self, username):
        return User(name=username, auth_plugin="mysql_native_password")
    def get_default_plugin(self):
        return self.get_plugins()[0]

async def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3308
    srv = MysqlServer(session_factory=Session, identity_provider=Provider(), host="0.0.0.0", port=port)
    print(f"[fake-mysql] listening on 0.0.0.0:{port} (accept ANY username/password)", flush=True)
    await srv.serve_forever()

asyncio.run(main())
