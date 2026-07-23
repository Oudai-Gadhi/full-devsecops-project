from flask import Flask
from routes.reports import reports_bp
from dotenv import load_dotenv
load_dotenv()
app = Flask(__name__)
app.register_blueprint(reports_bp)

@app.route("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
