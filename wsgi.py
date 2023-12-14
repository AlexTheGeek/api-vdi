from main import app, db, User, get_random_string
from argon2 import PasswordHasher
import logging
import os

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
# logger.debug('This is a debug message')
# logger.info('This is an info message')
# logger.warning('This is a warning message')
# logger.error('This is an error message')
# logger.critical('This is a critical message')


if __name__ == "__main__":
    logger.info('Starting API')
    with app.app_context():
        logger.info('Creating DB')
        db.create_all()
        db.session.commit()
        # Create default admin user
        if not User.query.filter_by(email="openstack@insa-cvl.fr").first():
            random_password = get_random_string(15)
            hashed_password = PasswordHasher().hash(random_password) 
            new_user = User(id="1", email="openstack@insa-cvl.fr", first_name="openstack", last_name="openstack",
                            password=hashed_password, role="admin", cas=True)
            db.session.add(new_user)
            db.session.commit()
            logger.info("Default admin user created with password: "+random_password)
            # print("Default admin user created with password: "+random_password)
    logger.info('API started')
    app.run()