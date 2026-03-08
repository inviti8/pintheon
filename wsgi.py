import config  # noqa: F401 — ensure config is loaded before app
from pintheon import app

if __name__ == '__main__':
    app.run(host=config.HOST, port=config.PORT)
