from flask import Flask, render_template, request, jsonify
import re
import secrets
import string

app = Flask(__name__)


def check_password_strength(password):
    suggestions = []

    if len(password) < 8:
        suggestions.append("Use at least 8 characters.")
    if not re.search(r"[A-Z]", password):
        suggestions.append("Include at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        suggestions.append("Include at least one lowercase letter.")
    if not re.search(r"\d", password):
        suggestions.append("Include at least one number.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        suggestions.append("Include at least one special character.")

    if len(password) >= 12 and all([
        re.search(r"[A-Z]", password),
        re.search(r"[a-z]", password),
        re.search(r"\d", password),
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    ]):
        return "Strong", "Your password is strong!", []

    if not suggestions:
        return "Moderate", "Your password is okay but could be stronger.", suggestions
    else:
        return "Weak", "Your password is weak.", suggestions


def generate_strong_password(length=12):
    if not isinstance(length, int) or length < 12:
        raise ValueError("Password length must be an integer of at least 12.")

    required = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*(),.?\":{}|<>"),
    ]
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*(),.?\":{}|<>"
    password = required + [secrets.choice(alphabet) for _ in range(length - len(required))]
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/check', methods=['POST'])
def check():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not isinstance(password, str):
        return jsonify({"error": "Password must be a string."}), 400
    if len(password) > 1024:
        return jsonify({"error": "Password must be 1024 characters or fewer."}), 400
    strength, message, suggestions = check_password_strength(password)
    return jsonify({
        "strength": strength,
        "message": message,
        "suggestions": " ".join(suggestions)
    })


@app.route('/generate')
def generate():
    password = generate_strong_password()
    return jsonify({"password": password})


if __name__ == '__main__':
    app.run(debug=False)
