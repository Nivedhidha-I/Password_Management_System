import json
from flask import Flask, request, jsonify
import requests
from hashlib import sha1
from argon2 import PasswordHasher, exceptions
import random

pass_db = "pass_db.json"
pass_policy_db = "pass_policy_db.json"

def new_app_password_policy(app_name, length, cap, small, num, special, not_include):
    try:
        with open(pass_policy_db, "r") as f:
            app_policies = json.load(f)
    except FileNotFoundError:
        app_policies = {}
    
    if not app_policies or app_name not in app_policies:
        next_app_id = 1 if not app_policies else max(policy["app_id"] for policy in app_policies.values()) + 1
        app_policies[app_name] = {
            "app_id": next_app_id,
            "length": length,
            "cap": cap,
            "small": small,
            "num": num,
            "special": special,
            "not_include": not_include,
        }
    else:
        return jsonify({"error": "Policy already exists for the mentioned application."}), 400
    
    with open("pass_policy_db.json", "w") as f:
        json.dump(app_policies, f, indent=4)
    return jsonify({"message": "New application password policy created successfully"}), 201

def change_password_policy(app_id, length, cap, small, num, special, not_include):
    try:
        with open(pass_policy_db, "r") as f:
            app_policies = dict(json.load(f))
        found = False
        for app_name, app_data in app_policies.items():
            if app_data["app_id"] == app_id:
                app_policies[app_name] = {
                    "app_id": app_id,
                    "length": length,
                    "cap": cap,
                    "small": small,
                    "num": num,
                    "special": special,
                    "not_include": not_include,
                }
                found = True
                break
        if not found:
            return jsonify({"error": f"Application password policy with app_id {app_id} not found."}), 404

        with open(pass_policy_db, "w") as f:
            json.dump(app_policies, f, indent=4)

        return jsonify({"message": "Application password policy updated successfully."}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400

def check_password_pwned(password_hash):
    try:
        prefix, suffix = password_hash[:5], password_hash[5:]

        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        response.raise_for_status()

        for line in response.text.splitlines():
            if line.split(':')[0] == suffix:
                return True
        return False

    except requests.exceptions.RequestException as e:
        print(f"Error making request to HIBP API: {e}")
        return False

def hash_password(password):
    ph = PasswordHasher()
    return ph.hash(password)

def generate_password(length, cap, small, num, special, not_include): 
    capL = [chr(i) for i in range(65, 91)]
    smallL = [chr(i) for i in range(97, 123)]
    numL = [chr(i) for i in range(48, 58)]
    specialL = [chr(i) for i in range(32, 48)] + [chr(i) for i in range(58, 65)] + [chr(i) for i in range(91, 97)] + [chr(i) for i in range(123, 127)]
    allL = capL + smallL + numL + specialL
    for i in not_include:
        if i in capL:
            capL.remove(i)
        if i in smallL:
            smallL.remove(i)
        if i in numL:
            numL.remove(i)
        if i in specialL:
            specialL.remove(i)
        if i in allL:
            allL.remove(i)
    while True:
        password = [] 
        if capL: 
            for i in range(cap):
                password.append(random.choice(capL))
            length -= cap
        if smallL:
            for i in range(small):
                password.append(random.choice(smallL))
            length -= small
        if numL:
            for i in range(num):
                password.append(random.choice(numL))
            length -= num
        if specialL:
            for i in range(special):
                password.append(random.choice(specialL))
            length -= special
        for i in range(length):
            password.append(random.choice(allL))
        random.shuffle(password)
        password = ''.join(password)
        password_hash = sha1(password.encode('utf-8')).hexdigest().upper()
        if not check_password_pwned(password_hash):
            return password, hash_password(password)

def verify_password(hashed_password, password): 
    try:
        ph = PasswordHasher() 
        ph.verify(hashed_password, password)
        return True
    except exceptions.VerifyMismatchError:
        return False

app = Flask(__name__)

@app.route('/add_new_policy', methods=['POST'])
def new_app_password_policy_endpoint():
    try:
        app_name = request.args.get('app_name')
        length = int(request.args.get('length', 12))
        cap = int(request.args.get('cap', 0))
        small = int(request.args.get('small', 0))
        num = int(request.args.get('num', 0))
        special = int(request.args.get('special', 0))
        not_include = list(set(request.args.get('not_include', [])))
        print(app_name, length, cap, small, num, special, not_include)

        if not app_name:
            return jsonify({"error": "App name is required"}), 400
        elif length < (cap + small + num + special):
            return jsonify({"error": "The password policy is incorrect."}), 400
        elif length < 0 or small < 0 or cap < 0 or special < 0 or num < 0:
            return jsonify({"error": "The password policy is incorrect."}), 400
        return new_app_password_policy(app_name, length, cap, small, num, special, not_include)

    except Exception as e:
        return jsonify({"error": str(e)}), 400
  
# in the user interface, the form can already contain the existing values to be sent and if we want we can change and then when 
# the form submited this function gets executed. which means, all the data gets sent
@app.route('/change_policy', methods=['POST'])
def change_password_policy_endpoint():
    try:
        app_id = int(request.args.get('app_id'))
        length = int(request.args.get('length', 12))
        cap = int(request.args.get('cap', 0))
        small = int(request.args.get('small', 0))
        num = int(request.args.get('num', 0))
        special = int(request.args.get('special', 0))
        not_include = list(set(request.args.get('not_include', [])))

        if not app_id:
            return jsonify({"error": "App ID is required"}), 400
        elif length < (cap + small + num + special):
            return jsonify({"error": "The password policy is incorrect."}), 400
        elif length < 0 or small < 0 or cap < 0 or special < 0 or num < 0:
            return jsonify({"error": "The password policy is incorrect."}), 400
        
        return change_password_policy(app_id, length, cap, small, num, special, not_include)

    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/generate_password', methods=['POST'])
def generate_password_endpoint():
    try:
        app_id = request.args.get('app_id')
        user_id = request.args.get('user_id')

        if not app_id or not user_id:
            return jsonify({"error": "both app_id and user_id are required"}), 400
        
        app_id = int(app_id)
        user_id = int(user_id)
        try:
            with open(pass_policy_db, "r") as f:
                app_policies = dict(json.load(f))
        except FileNotFoundError:
            return jsonify({"error": "Password policy file not found."}), 500
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON in password policy file."}), 500
        except Exception as e:
            return jsonify({"error": f"Error reading password policy file: {e}"}), 500
        
        if not app_policies:
            return jsonify({"error": "No application policies found."}), 404

        not_found_policy = True
        for app_data in app_policies.values():
            if app_data["app_id"] == app_id:
                length = app_data["length"]
                cap = app_data["cap"]
                small = app_data["small"]
                num = app_data["num"]
                special = app_data["special"]
                not_include = app_data["not_include"]
                password, password_hash = generate_password(length, cap, small, num, special, not_include)
                not_found_policy = False
                break

        if not_found_policy:
            return jsonify({"error": "app_id not registered in PMS"}), 400

        try:
            with open(pass_db, "r") as f:
                user_pass = json.load(f)
        except json.JSONDecodeError:
            user_pass = {}

        updated_user_pass = {}
        found_existing_entry = False
        for row_id, user_data in user_pass.items():
            if user_data["user_id"] == int(user_id) and user_data["app_id"] == app_id:
                user_data["password_hash"] = password_hash 
                updated_user_pass[row_id] = user_data
                found_existing_entry = True
                break 
            else:
                updated_user_pass[row_id] = user_data 

        if not found_existing_entry:
            next_row_id = 1 if not user_pass else max(int(user) for user in user_pass.keys()) + 1
            updated_user_pass[str(next_row_id)] = { 
                "user_id": user_id, 
                "app_id": app_id, 
                "password_hash": password_hash 
            }
        
        with open(pass_db, "w") as f:
            json.dump(updated_user_pass, f, indent=4)

        return jsonify({"message": f"Password generated successfully. The password is {password}"}), 200
    
    except TypeError:
        return jsonify({"error": "Data is of incorrect type"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/verify_password', methods=['POST'])
def verify_password_endpoint():
    try:
        user_id = request.args.get('user_id')
        app_id = request.args.get('app_id')
        password = request.args.get('password')
        if not user_id or not app_id or not password:
            return jsonify({"error": "user_id, app_id, and password are required"}), 400
        user_id = int(user_id)
        app_id = int(app_id)
        with open(pass_db, "r") as f:
            user_passwords = json.load(f)
        found_password = False
        for user_data in user_passwords.values():
            if user_data["user_id"] == user_id and user_data["app_id"] == app_id:
                hashed_password = user_data["password_hash"]
                found_password = True
                break

        if not found_password:
            return jsonify({"error": "User or application not found"}), 404
        if verify_password(hashed_password, password):
            return jsonify({"message": "Login successful"}), 200
        else:
            return jsonify({"error": "Incorrect password"}), 401
        
    except Exception as e:
        return jsonify({"error": "Internal server error: " + str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True) 