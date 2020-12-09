from app_package import app, db
from app_package.models import User


@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User}
