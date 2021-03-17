from pydantic import BaseModel
from flask import Flask, jsonify, request

app = Flask(__name__)

class AddUserCommand(BaseModel):
    username : Str
    name : str

    def execute(self) -> User:
        user = User(
            username=self.username,
            name=self.name,
            is_active=True
        )
        user.save()

        return user