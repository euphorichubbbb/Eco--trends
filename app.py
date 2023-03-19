from flask import Flask, render_template, redirect, request, session, url_for, flash
from secret_key_generator import secret_key_generator
from datetime import datetime
from flask_bcrypt import Bcrypt
import psycopg2
from config import config
from datetime import datetime

app = Flask(__name__)
app.config["SECRET_KEY"] = secret_key_generator.generate()
bcrypt = Bcrypt(app)
conn = None


@app.route("/")
@app.route("/home")
def home() -> str:
    """Display home page
    :return: str - a template
    """
    return render_template("home.html")


@app.route("/signup", methods=["GET", "POST"])
def register() -> str:
    """Allow user to register in the platform
    :return: str - signup form
    """

    # if session has already been established no need to signup
    if "user_name" in session:
        return render_template(
            "home.html", value="none", value_for_icon="block", user=session["user_name"]]
        )
    if request.method == "POST":
        # collect user data from the  form and save in the database
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        user_name = request.form["user_name"]
        password = request.form["user_password1"]
        repeat_password = request.form["user_password2"]
        created_on = datetime.now()
        last_login = created_on
        print(request.form)
        if password == repeat_password:
            # save data in the db, no redundancy
            hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
            is_successful = False
            params = config()
            conn = psycopg2.connect(**params)
            db_cursor = conn.cursor()
            try:
                db_cursor.execute(
                    """INSERT INTO users (user_name, first_name, last_name, password, created_on, last_login) 
                                     VALUES (%s, %s, %s, %s, %s, %s)""",
                    (
                        user_name,
                        first_name,
                        last_name,
                        hashed_password,
                        created_on,
                        last_login,
                    ),
                )
            except (Exception, psycopg2.DatabaseError) as error:
                with open("error_logs", mode="a", encoding="utf-8") as file_handle:
                    print(error, file=file_handle)
                flash("There was an error during signup try again", "error")
            else:
                conn.commit()
                is_successful = True
            finally:
                db_cursor.close()
                if conn is not None:
                    conn.close()
                if is_successful:
                    session["user_name"] = user_name
                    return render_template(
                        "home.html",
                        value="none",
                        value_for_icon="block",
                        user=user_name,
                    )
                return redirect(url_for("register"))

        # when password 1 & 2 do not match
        flash("Password does not match try again", "error")
        return redirect(url_for("register"))
    return render_template("signup.html", value="none")


@app.route("/login", methods=["GET", "POST"])
def login() -> str:
    """authenticate user to access system
    :return: str - login form
    """

    # check if there is active session
    # then collect user data if no session available
    # initialize a new session
    if "user_name" in session:
        return render_template(
            "home.html", value="none", value_for_icon="block", user=session["user_name"]
        )
    if request.method == "POST":
        user_name = request.form["user_name"]
        user_password = request.form["user_password"]

        # password validation
        params = config()
        conn = psycopg2.connect(**params)
        db_cursor = conn.cursor()
        hashed_password = None
        login_successful = False
        try:
            db_cursor.execute(
                "SELECT password FROM users WHERE user_name = %s", (user_name,)
            )
            hashed_password = db_cursor.fetchone()
        except Exception:
            print(Exception)
        else:
            if bcrypt.check_password_hash(hashed_password[0], user_password):
                db_cursor.execute(
                    "UPDATE users SET last_login = %s WHERE user_name = %s",
                    (datetime.now(), user_name),
                )
                session["user_name"] = user_name
                login_successful = True
        finally:
            conn.commit()
            db_cursor.close()
            conn.close()
        if login_successful:
            flash("Login Successful")
            return render_template(
                "home.html", value="none", value_for_icon="block", user=user_name
            )
        flash("Password or Username incorrect", "error")
        return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/profile/<user_name>")
def profile(user_name) -> str:
    """Display user profile
    :param user_name: str - user unique identifier
    :return: str - a user profile page
    """

    if "user_name" in session:
        return render_template("profile.html", value="none", value_for_icon="block")
    return redirect(url_for("login"))


@app.route("/profile_update", methods=["GET", "POST"])
def update_profile() -> str:
    """Handle update profile submissions
    :return: str - updated profile
    """

    if "user_name" in session:
        # upload details to the user_information table
        if request.method == "POST":
            email_address = request.form["email_address"]
            phone_number = request.form["phone_number"]
            zip_code = request.form["zip_code"]
            country = request.form["country"]
            city = request.form["city"]
            street = request.form["street"]
            house_number = request.form["house_number"]

            params = config()
            conn = psycopg2.connect(**params)
            db_cursor = conn.cursor()
            operation_successful = False
            try:
                db_cursor.execute(
                    """INSERT INTO contact_informations (email_address, phone_number, user_name)
                                    VALUES (%s, %s, %s)""",
                    (email_address, phone_number, session["user_name"]),
                )
                db_cursor.execute(
                    """INSERT INTO address (zip_code, country, city, street, house_number)
                                    VALUES (%s, %s, %s, %s, %s)""",
                    (zip_code, country, city, street, house_number),
                )
            except Exception:
                with open("error_logs", mode="a", encoding="utf-8") as file_handle:
                    print(Exception, file = file_handle)
            else:
                flash("Profile update successfully")
                operation_succesful = True
                conn.commit()
            finally:
                db_cursor.close()
                conn.close()
                if operation_successful:
                    return redirect(url_for("profile"))
                return redirect(url_for("update_profile"))
    # return redirect(url_for("profile"))
    return redirect(url_for("login"))

@app.route(
if __name__ == "__main__":
    app.run(debug=True, port=3000)
