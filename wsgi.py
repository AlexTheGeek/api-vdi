from main import app, db, User, get_random_string
from argon2 import PasswordHasher

if __name__ == "__main__":
    with app.app_context():
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
            print("Default admin user created with password: "+random_password)
    app.run()