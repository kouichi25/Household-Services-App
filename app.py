from flask import Flask, render_template

app = Flask(__name__)
import config
import routs
import models



if __name__ == "__main__":
    app.run(debug=True)