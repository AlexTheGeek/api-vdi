##################
### Librairies ###
##################
from main import app, db, User, get_random_string
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from argon2 import PasswordHasher
import logging
import os


db = SQLAlchemy(app)
migrate = Migrate(app, db)

##################
### Log config ###
##################
# Create a custom logger
logger = logging.getLogger("API-VDI")
logging.basicConfig(level = logging.INFO)

# Create handlers
if not os.path.exists('/var/log/VDI/API'):
    os.makedirs('/var/log/VDI/API')
    os.system("chown -R alex:alex /var/log/VDI")
f_handler = logging.FileHandler('/var/log/VDI/API/api-flask.log')
f_handler.setLevel(logging.INFO)

# Create formatters and add it to handlers
f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
f_handler.setFormatter(f_format)

# Add handlers to the logger
logger.addHandler(f_handler)

############
### Main ###
############
if __name__ == "__main__":
    logger.info('Starting API')
    with app.app_context():
        logger.info('Creating DB')
        db.create_all()
        db.session.commit()
        # Create default admin user
        if not User.query.filter_by(email="admin@admin.fr").first():
            logger.info('Creating default admin user')
            random_password = "admin"
            hashed_password = PasswordHasher().hash(random_password) 
            new_user = User(id="2", email="admin@admin.fr", first_name="Admin", last_name="VDI",
                            password=hashed_password, role="admin", cas=False)
            db.session.add(new_user)
            db.session.commit()
            logger.info("Default admin user created with password: "+random_password)
        # Create default prof user
        if not User.query.filter_by(email="prof@prof.fr").first():
            logger.info('Creating default prof user')
            random_password = "prof"
            hashed_password = PasswordHasher().hash(random_password) 
            new_user = User(id="3", email="prof@prof.fr", first_name="Prof", last_name="VDI",
                            password=hashed_password, role="prof", cas=False)
            db.session.add(new_user)
            db.session.commit()
            logger.info("Default prof user created with password: "+random_password)
        # Create default etudiant user
        if not User.query.filter_by(email="etudiant@etudiant.fr").first():
            logger.info('Creating default etudiant user')
            random_password = "etudiant"
            hashed_password = PasswordHasher().hash(random_password) 
            new_user = User(id="4", email="etudiant@etudiant.fr", first_name="Etudiant", last_name="VDI",
                            password=hashed_password, role="user", cas=False)
            db.session.add(new_user)
            db.session.commit()
            logger.info("Default etudiant user created with password: "+random_password)
    logger.info('API started')
    app.run()