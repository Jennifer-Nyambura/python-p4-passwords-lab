#!/usr/bin/env python3
from flask import request, session, jsonify
from flask_restful import Resource
from config import app, db, api, bcrypt
from models import User


# ------------------ SIGNUP ------------------
class Signup(Resource):
    def post(self):
        data = request.get_json()

        username = data.get("username")
        password = data.get("password")
        password_confirmation = data.get("password_confirmation")

        # Basic password confirmation check
        if password != password_confirmation:
            return {"error": "Passwords do not match"}, 400

        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        # Create user
        new_user = User(username=username, password_hash=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        # Save user in session
        session["user_id"] = new_user.id

        return new_user.to_dict(), 201


# ------------------ LOGIN ------------------
class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            session["user_id"] = user.id
            return user.to_dict(), 200

        return {"error": "Invalid username or password"}, 401


# ------------------ LOGOUT ------------------
class Logout(Resource):
    def delete(self):
        session.pop("user_id", None)
        return {}, 204


# ------------------ CHECK SESSION ------------------
class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")

        if user_id:
            user = User.query.get(user_id)
            if user:
                return user.to_dict(), 200

        return {}, 204


# ------------------ ROUTES ------------------
api.add_resource(Signup, "/signup")
api.add_resource(Login, "/login")
api.add_resource(Logout, "/logout")
api.add_resource(CheckSession, "/check_session")


# ------------------ RUN SERVER ------------------
if __name__ == "__main__":
    app.run(port=5555, debug=True)
