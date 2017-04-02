from werkzeug.contrib.fixers import ProxyFix

from cvechk import app


app.wsgi_app = ProxyFix(app.wsgi_app)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
