from flask import Flask, request, jsonify
from signer import generate_signed_url

app = Flask(__name__)

@app.route("/sign", methods=["POST"])
def sign_url():
    data = request.get_json()
    url = data.get("url")
    if not url:
        return jsonify({"error": "Missing URL"}), 400

    signed_url = generate_signed_url(url)
    return jsonify({"signed_url": signed_url})

if __name__ == "__main__":
    app.run(host="localhost", port=5410)