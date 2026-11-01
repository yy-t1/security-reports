import asyncio, sys
from mysql_mimic import MysqlServer, Session
from mysql_mimic.auth import SimpleIdentityProvider

async def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3307
    srv = MysqlServer(session_factory=Session, identity_provider=SimpleIdentityProvider(), host="0.0.0.0", port=port)
    print(f"[fake-mysql] listening on 0.0.0.0:{port} (accept any username, empty password)", flush=True)
    await srv.serve_forever()

asyncio.run(main())
