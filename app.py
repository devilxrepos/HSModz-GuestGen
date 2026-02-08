from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_file
import hsmodz
import json
import os
import hashlib
import uuid
from datetime import datetime, timedelta
import secrets

app = Flask(__name__)
app.secret_key = "HSMODZ-FF-2024"

# 🔐 Admin credentials
USERNAME = "admin"
PASSWORD = "admin123"

# 🔑 License system
LICENSE_KEY = "HSMODZ-FF-2024"  # Change this to your secret license key
LICENSE_EXPIRY_DAYS = 30  # License validity in days

# File paths
GENERATED_ACCOUNTS_FILE = "generated_accounts.json"
LICENSE_FILE = "licenses.json"
LOG_FILE = "auth_log.txt"

# ---------- HELPER FUNCTIONS ----------
def generate_license(username, email=None):
    """Generate a new license key"""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    unique_id = secrets.token_hex(4).upper()
    license_key = f"FF-{timestamp}-{unique_id}"
    
    # Create license data
    license_data = {
        "license_key": license_key,
        "username": username,
        "email": email,
        "created_at": datetime.now().isoformat(),
        "expires_at": (datetime.now() + timedelta(days=LICENSE_EXPIRY_DAYS)).isoformat(),
        "is_active": True,
        "usage_count": 0,
        "max_accounts": 1000,  # Maximum accounts this license can generate
        "generated_accounts": 0
    }
    
    # Save to file
    licenses = load_licenses()
    licenses[license_key] = license_data
    save_licenses(licenses)
    
    log_auth(f"License generated for {username} ({email}): {license_key}")
    return license_key, license_data

def validate_license(license_key):
    """Validate a license key"""
    licenses = load_licenses()
    
    if license_key not in licenses:
        log_auth(f"Invalid license attempt: {license_key}")
        return False, "Invalid license key"
    
    license_data = licenses[license_key]
    
    # Check if license is active
    if not license_data.get("is_active", True):
        log_auth(f"Inactive license: {license_key}")
        return False, "License is inactive"
    
    # Check expiry
    expires_at = datetime.fromisoformat(license_data["expires_at"])
    if datetime.now() > expires_at:
        log_auth(f"Expired license: {license_key}")
        return False, "License has expired"
    
    # Check account limit
    if license_data.get("generated_accounts", 0) >= license_data.get("max_accounts", 1000):
        log_auth(f"License limit reached: {license_key}")
        return False, "Account generation limit reached"
    
    log_auth(f"Valid license: {license_key}")
    return True, license_data

def update_license_usage(license_key, accounts_generated=1):
    """Update license usage statistics"""
    licenses = load_licenses()
    
    if license_key in licenses:
        licenses[license_key]["usage_count"] = licenses[license_key].get("usage_count", 0) + 1
        licenses[license_key]["generated_accounts"] = licenses[license_key].get("generated_accounts", 0) + accounts_generated
        licenses[license_key]["last_used"] = datetime.now().isoformat()
        save_licenses(licenses)
        return True
    return False

def load_licenses():
    """Load licenses from file"""
    if os.path.exists(LICENSE_FILE):
        try:
            with open(LICENSE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_licenses(licenses):
    """Save licenses to file"""
    with open(LICENSE_FILE, "w", encoding="utf-8") as f:
        json.dump(licenses, f, indent=2, ensure_ascii=False)

def log_auth(message):
    """Log authentication events"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_entry)
    print(log_entry.strip())

def get_license_info(license_key):
    """Get license information"""
    licenses = load_licenses()
    return licenses.get(license_key)

# ---------- ROUTES ----------

@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        secret_key = request.form.get("secret_key")
        
        if not username or not email or not secret_key:
            return render_template("register.html", error="All fields are required")
        
        # Validate secret key
        if secret_key != LICENSE_KEY:
            log_auth(f"Invalid secret key attempt from {username} ({email})")
            return render_template("register.html", error="Invalid secret key")
        
        # Generate license
        license_key, license_data = generate_license(username, email)
        
        return render_template("license_result.html", 
                             license_key=license_key,
                             username=username,
                             email=email,
                             expires_at=license_data["expires_at"])
    
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        license_key = request.form.get("license_key", "").strip()
        
        if not license_key:
            return render_template("login.html", error="License key is required")
        
        # Validate license
        is_valid, message = validate_license(license_key)
        
        if is_valid:
            session["logged_in"] = True
            session["license_key"] = license_key
            session["license_info"] = get_license_info(license_key)
            log_auth(f"Successful login with license: {license_key}")
            return redirect(url_for("dashboard"))
        else:
            log_auth(f"Failed login attempt: {license_key} - {message}")
            return render_template("login.html", error=message)
    
    return render_template("login.html")

@app.route("/logout")
def logout():
    if session.get("license_key"):
        log_auth(f"User logged out: {session['license_key']}")
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    license_info = session.get("license_info", {})
    return render_template("dashboard.html", license_info=license_info)

@app.route("/license_info")
def license_info():
    if not session.get("logged_in"):
        return jsonify({"status": "unauthorized"}), 401
    
    license_key = session.get("license_key")
    info = get_license_info(license_key)
    
    if info:
        # Calculate remaining days
        expires_at = datetime.fromisoformat(info["expires_at"])
        days_remaining = (expires_at - datetime.now()).days
        info["days_remaining"] = max(0, days_remaining)
        
        # Calculate remaining accounts
        max_accounts = info.get("max_accounts", 1000)
        generated = info.get("generated_accounts", 0)
        info["remaining_accounts"] = max(0, max_accounts - generated)
    
    return jsonify({"status": "success", "license_info": info})

@app.route("/generate", methods=["POST"])
def generate():
    if not session.get("logged_in"):
        return jsonify({"status": "unauthorized"}), 401
    
    license_key = session.get("license_key")
    
    # Validate license again (in case it expired during session)
    is_valid, message = validate_license(license_key)
    if not is_valid:
        session.clear()
        return jsonify({"status": "error", "message": f"License invalid: {message}"}), 401
    
    region = request.form.get("region")
    prefix = request.form.get("prefix", "hsmodz")
    count = request.form.get("count", "1")
    
    if not region:
        return jsonify({"status": "error", "message": "Region required"})
    
    try:
        count = int(count)
        if count < 1 or count > 50:  # Limit per batch for performance
            return jsonify({"status": "error", "message": "Count must be between 1 and 50"})
        
        # Check license limits
        license_info = get_license_info(license_key)
        remaining = license_info.get("max_accounts", 1000) - license_info.get("generated_accounts", 0)
        if count > remaining:
            return jsonify({"status": "error", "message": f"License limit reached. Only {remaining} accounts remaining."})
            
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid count number"})
    
    # Generate multiple accounts
    accounts = []
    errors = []
    
    for i in range(count):
        try:
            result = hsmodz.web_generate_account(region.upper(), prefix)
            if result.get("status") == "success":
                accounts.append(result)
            else:
                errors.append(f"Account {i+1}: {result.get('message', 'Unknown error')}")
        except Exception as e:
            errors.append(f"Account {i+1}: {str(e)}")
    
    # Update license usage
    if accounts:
        update_license_usage(license_key, len(accounts))
        save_accounts_to_file(accounts, region, prefix, license_key)
        log_auth(f"License {license_key} generated {len(accounts)} accounts for region {region}")
    
    return jsonify({
        "status": "batch_complete",
        "successful": len(accounts),
        "failed": len(errors),
        "accounts": accounts,
        "errors": errors if errors else None,
        "download_available": len(accounts) > 0,
        "license_remaining": remaining - len(accounts)
    })

@app.route("/download")
def download():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    if os.path.exists(GENERATED_ACCOUNTS_FILE):
        return send_file(
            GENERATED_ACCOUNTS_FILE,
            as_attachment=True,
            download_name=f"freefire_accounts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
    return jsonify({"status": "error", "message": "No accounts to download"})

@app.route("/admin", methods=["GET", "POST"])
def admin():
    """Admin panel for managing licenses"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if username == USERNAME and password == PASSWORD:
            session["admin_logged_in"] = True
            return redirect(url_for("admin_panel"))
        else:
            return render_template("admin_login.html", error="Invalid credentials")
    
    return render_template("admin_login.html")

@app.route("/admin/panel")
def admin_panel():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin"))
    
    licenses = load_licenses()
    return render_template("admin_panel.html", licenses=licenses)

@app.route("/admin/create_license", methods=["POST"])
def create_license_admin():
    if not session.get("admin_logged_in"):
        return jsonify({"status": "unauthorized"}), 401
    
    username = request.form.get("username")
    email = request.form.get("email")
    days = int(request.form.get("days", LICENSE_EXPIRY_DAYS))
    max_accounts = int(request.form.get("max_accounts", 1000))
    
    if not username:
        return jsonify({"status": "error", "message": "Username required"})
    
    # Generate license
    license_key, license_data = generate_license(username, email)
    
    # Update custom values
    licenses = load_licenses()
    if license_key in licenses:
        licenses[license_key]["expires_at"] = (datetime.now() + timedelta(days=days)).isoformat()
        licenses[license_key]["max_accounts"] = max_accounts
        save_licenses(licenses)
    
    log_auth(f"Admin created license: {license_key} for {username}")
    return jsonify({
        "status": "success", 
        "license_key": license_key,
        "license_data": licenses[license_key]
    })

@app.route("/admin/toggle_license/<license_key>", methods=["POST"])
def toggle_license(license_key):
    if not session.get("admin_logged_in"):
        return jsonify({"status": "unauthorized"}), 401
    
    licenses = load_licenses()
    if license_key in licenses:
        licenses[license_key]["is_active"] = not licenses[license_key].get("is_active", True)
        save_licenses(licenses)
        
        action = "activated" if licenses[license_key]["is_active"] else "deactivated"
        log_auth(f"Admin {action} license: {license_key}")
        
        return jsonify({"status": "success", "is_active": licenses[license_key]["is_active"]})
    
    return jsonify({"status": "error", "message": "License not found"})

@app.route("/admin/delete_license/<license_key>", methods=["POST"])
def delete_license(license_key):
    if not session.get("admin_logged_in"):
        return jsonify({"status": "unauthorized"}), 401
    
    licenses = load_licenses()
    if license_key in licenses:
        del licenses[license_key]
        save_licenses(licenses)
        log_auth(f"Admin deleted license: {license_key}")
        return jsonify({"status": "success"})
    
    return jsonify({"status": "error", "message": "License not found"})

def save_accounts_to_file(accounts, region, prefix, license_key):
    """Save generated accounts to a JSON file"""
    data = {
        "generated_at": datetime.now().isoformat(),
        "region": region,
        "prefix": prefix,
        "license_key": license_key,
        "total_accounts": len(accounts),
        "accounts": accounts
    }
    
    with open(GENERATED_ACCOUNTS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    return True

if __name__ == "__main__":
    # Create necessary files if they don't exist
    if not os.path.exists(LICENSE_FILE):
        save_licenses({})
    
    app.run(host="0.0.0.0", port=5000, debug=True)