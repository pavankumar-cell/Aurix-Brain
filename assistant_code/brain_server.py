from flask import Flask, request, jsonify
import os
import datetime
import time
import hmac
import wikipedia
import re
import random
import hashlib
from urllib.parse import urlparse
import requests
import sqlite3
import uuid
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(app=app, key_func=get_remote_address)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

COMMAND_LOG_FOLDER = os.path.join(BASE_DIR, "commands_logs")
IMAGE_CACHE_FOLDER = os.path.join(BASE_DIR, "image_cache")
BRAIN_FOLDER = os.path.join(BASE_DIR, "brain")
DB_FILE = os.path.join(BASE_DIR, "brain.db")
API_KEYS_FILE = os.path.join(BASE_DIR, "api_keys.json")
REQUEST_TIMEOUT = 60  # seconds - reject requests older than 60 seconds

os.makedirs(COMMAND_LOG_FOLDER, exist_ok=True)
os.makedirs(IMAGE_CACHE_FOLDER, exist_ok=True)
os.makedirs(BRAIN_FOLDER, exist_ok=True)

DICTIONARY_FILE = os.path.join(BRAIN_FOLDER, "dictionary.json")
PATTERNS_FILE = os.path.join(BRAIN_FOLDER, "patterns.json")
MEMORY_FILE = os.path.join(BRAIN_FOLDER, "memory.json")
CORRECTIONS_FILE = os.path.join(BRAIN_FOLDER, "corrections.json")

# Authentication config
import json
AUTH_ENABLED = True
ALLOW_NEW_REGISTRATIONS = True  # ⭐ False = Disable new device registrations, True = Allow anyone to register new devices (default: True for ease of use, set to False for production security)
VALID_API_KEYS = {}
DEVICE_IDS = {}

dictionary_data = {}
patterns_data = {}
memory_data = {}
corrections_data = {}


def load_json_file(filepath, default=None):
    if default is None:
        default = {}
    if not os.path.exists(filepath):
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=2, ensure_ascii=False)
        return default
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except (UnicodeDecodeError, json.JSONDecodeError):
        try:
            with open(filepath, "r", encoding="cp1252") as f:
                data = json.load(f)
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return data
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=2, ensure_ascii=False)
        return default

@app.route("/send_command", methods=["POST"])
def receive_command():
    data = request.json
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    with open(f"{COMMAND_LOG_FOLDER}/{timestamp}.txt", "w") as f:
        f.write(str(data))
    
    # Log to database
    log_command_to_db(data.get('command'), 'single')
    
    return jsonify({"status": "received"})


def init_database():
    """Initialize SQLite database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        # Create tables
        c.execute('''CREATE TABLE IF NOT EXISTS commands
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      command TEXT,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                      source TEXT,
                      device_id TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS api_keys
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      api_key TEXT UNIQUE,
                      device_id TEXT UNIQUE,
                      device_name TEXT,
                      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                      last_used DATETIME,
                      active INTEGER DEFAULT 1)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS queries
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      query TEXT,
                      response TEXT,
                      source TEXT,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                      device_id TEXT)''')
        
        conn.commit()
        conn.close()
        print("[Database] Initialized successfully")
    except Exception as e:
        print(f"[Database] Initialization error: {e}")


def log_command_to_db(command, cmd_type, device_id="unknown"):
    """Log command to database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO commands (command, source, device_id) VALUES (?, ?, ?)",
                  (command, cmd_type, device_id))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Database] Log error: {e}")


def log_query_to_db(query, response, source, device_id="unknown"):
    """Log query to database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO queries (query, response, source, device_id) VALUES (?, ?, ?, ?)",
                  (query, response, source, device_id))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Database] Query log error: {e}")


def load_api_keys():
    """Load API keys from file"""
    global VALID_API_KEYS, DEVICE_IDS
    try:
        if os.path.exists(API_KEYS_FILE):
            with open(API_KEYS_FILE, 'r') as f:
                data = json.load(f)
                VALID_API_KEYS = {k: v for k, v in data.items() if v.get('active', True)}
                DEVICE_IDS = {v.get('device_id'): k for k, v in data.items() if v.get('active', True)}
        else:
            print("[Auth] No API keys file found. Creating default...")
            create_default_api_key()
    except Exception as e:
        print(f"[Auth] Load error: {e}")


def create_default_api_key():
    """Create a default API key for first setup"""
    try:
        api_key = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:32]
        device_id = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:16]
        
        data = {
            api_key: {
                "device_id": device_id,
                "device_name": "AURIX-Default",
                "created_at": datetime.datetime.now().isoformat(),
                "active": True
            }
        }
        
        with open(API_KEYS_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[Auth] Default API Key: {api_key}")
        print(f"[Auth] Device ID: {device_id}")
        print(f"[Auth] Save this to your desktop app config!")
        
        VALID_API_KEYS[api_key] = data[api_key]
        DEVICE_IDS[device_id] = api_key
    except Exception as e:
        print(f"[Auth] Create key error: {e}")


def add_api_key(device_name="Unknown Device"):
    """Add a new API key"""
    try:
        api_key = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:32]
        device_id = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:16]
        
        if os.path.exists(API_KEYS_FILE):
            with open(API_KEYS_FILE, 'r') as f:
                data = json.load(f)
        else:
            data = {}
        
        data[api_key] = {
            "device_id": device_id,
            "device_name": device_name,
            "created_at": datetime.datetime.now().isoformat(),
            "active": True
        }
        
        with open(API_KEYS_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[Auth] New API Key created: {api_key}")
        print(f"[Auth] Device: {device_name} | Device ID: {device_id}")
        
        VALID_API_KEYS[api_key] = data[api_key]
        DEVICE_IDS[device_id] = api_key
        
        return api_key, device_id
    except Exception as e:
        print(f"[Auth] Add key error: {e}")
        return None, None


def require_auth(f):
    """Decorator to require API key authentication with HMAC signature verification"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not AUTH_ENABLED:
            return f(*args, **kwargs)
        
        # Check API Key
        api_key = request.headers.get('X-API-Key')
        device_id = request.headers.get('X-Device-ID')
        timestamp_str = request.headers.get('X-Timestamp')
        signature = request.headers.get('X-Signature')
        
        if not api_key:
            return jsonify({"status": "error", "message": "Missing X-API-Key header"}), 401
        
        # Validate API key exists
        if api_key not in VALID_API_KEYS:
            print(f"[Auth] Invalid API key attempt: {api_key[:10]}...")
            return jsonify({"status": "error", "message": "Invalid API key"}), 401
        
        # Validate Device ID and enforce device-key matching
        if not device_id:
            return jsonify({"status": "error", "message": "Missing X-Device-ID header"}), 401
        
        # FIX 2: Enforce strict device-key matching
        expected_key = DEVICE_IDS.get(device_id)
        if expected_key != api_key:
            print(f"[Auth] Device-key mismatch: Device={device_id}, Key={api_key[:10]}...")
            return jsonify({
                "status": "error",
                "message": "Device ID does not match API key"
            }), 401
        
        # FIX 3: Validate request timestamp (anti-replay attack)
        if not timestamp_str:
            print(f"[Auth] Missing X-Timestamp header")
            return jsonify({"status": "error", "message": "Missing X-Timestamp header"}), 401
        
        try:
            request_timestamp = int(timestamp_str)
            current_timestamp = int(time.time())
            time_diff = abs(current_timestamp - request_timestamp)
            
            if time_diff > REQUEST_TIMEOUT:
                print(f"[Auth] Request too old: {time_diff}s > {REQUEST_TIMEOUT}s")
                return jsonify({
                    "status": "error",
                    "message": "Request timestamp expired (anti-replay protection)"
                }), 401
        except (ValueError, TypeError):
            print(f"[Auth] Invalid timestamp format: {timestamp_str}")
            return jsonify({"status": "error", "message": "Invalid timestamp format"}), 401
        
        # ⭐ FINAL FIX: HMAC Signature Verification (prevents stolen API key usage)
        if not signature:
            print(f"[Auth] Missing X-Signature header")
            return jsonify({"status": "error", "message": "Missing X-Signature header"}), 401
        
        # Generate expected signature
        message = api_key + device_id + timestamp_str
        expected_signature = hmac.new(
            api_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(signature, expected_signature):
            print(f"[Auth] Invalid signature from device: {device_id}")
            return jsonify({
                "status": "error",
                "message": "Invalid request signature (HMAC verification failed)"
            }), 401
        
        print(f"[Auth] ✓ HMAC verified - Device: {device_id}, API Key: {api_key[:10]}...")
        return f(*args, **kwargs)
    
    return decorated_function

@app.route("/send_commands", methods=["POST"])
def receive_commands():
    commands = request.json
    if not isinstance(commands, list):
        return jsonify({"status": "error", "message": "Expected a list of commands"}), 400
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{COMMAND_LOG_FOLDER}/{timestamp}_batch.txt"
    
    with open(filename, "w") as f:
        f.write(f"Received {len(commands)} commands:\n\n")
        for idx, cmd in enumerate(commands, 1):
            f.write(f"Command {idx}:\n")
            f.write(f"  Timestamp: {cmd.get('timestamp', 'N/A')}\n")
            f.write(f"  Command: {cmd.get('command', 'N/A')}\n\n")
            log_command_to_db(cmd.get('command'), 'batch')
    
    return jsonify({"status": "received", "count": len(commands)})


def clean_query(query):
    """Clean query for Wikipedia search"""
    query = query.lower()
    query = re.sub(r"\b(what is|who is|tell me about|define|explain|give me information about|do you know about)\b", "", query)
    return query.strip()


def download_image(url, folder):
    """Download image from URL to folder and return local path"""
    try:
        # Create a unique filename based on URL hash
        url_hash = hashlib.md5(url.encode()).hexdigest()
        parsed_url = urlparse(url)
        ext = os.path.splitext(parsed_url.path)[1] or '.jpg'
        filename = f"{url_hash}{ext}"
        filepath = os.path.join(folder, filename)
        
        # Check if already cached
        if os.path.exists(filepath):
            return filepath
        
        # Download the image with proper headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, timeout=10, stream=True, headers=headers)
        if response.status_code == 200:
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(1024):
                    f.write(chunk)
            return filepath
    except Exception as e:
        print(f"Error downloading image: {e}")
    return None


def answer_from_wikipedia(query):
    """Search Wikipedia and return summary with images"""
    try:
        wikipedia.set_lang("en")
        clean = clean_query(query)
        print(f"[Wikipedia] Searching for: '{clean}'")
        page = wikipedia.page(clean, auto_suggest=False)
        result = wikipedia.summary(clean, sentences=2, auto_suggest=False)
        print(f"[Wikipedia] Found: '{page.title}'")
        
        images = []
        try:
            image_urls = page.images[:10]
            SKIP_KEYWORDS = ['logo', 'icon', 'map', 'flag', 'seal']
            
            for img_url in image_urls:
                if not img_url:
                    continue
                
                lower = img_url.lower()
                if any(k in lower for k in SKIP_KEYWORDS):
                    continue
                if not lower.endswith(('.jpg', '.jpeg', '.png', '.webp', '.gif')):
                    continue
                
                # Return raw image URLs (let client download)
                images.append(img_url)
                
                if len(images) >= 10:
                    break
        except Exception as e:
            print(f"[Wikipedia] Error processing images: {e}")
        
        return {
            "source": "Wikipedia",
            "title": page.title,
            "text": result,
            "images": images
        }
    except wikipedia.DisambiguationError as e:
        print(f"[Wikipedia] Disambiguation error for '{query}': {e.options[:3] if hasattr(e, 'options') else 'N/A'}")
        return None
    except wikipedia.PageError as e:
        print(f"[Wikipedia] Page not found for '{query}'")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[Wikipedia] Upstream request failed for '{query}': {e}")
        return None
    except Exception as e:
        print(f"[Wikipedia] Error for '{query}': {type(e).__name__}: {e}")
        return None


def answer_from_duckduckgo(query):
    """Search DuckDuckGo and return result with images"""
    try:
        from ddgs import DDGS
        with DDGS(timeout=10) as ddgs:
            # Get text results
            results = list(ddgs.text(query, safesearch='Moderate', max_results=1))
            if results and len(results) > 0:
                first_result = results[0]
                if first_result and 'body' in first_result:
                    # Get images
                    images = []
                    try:
                        image_results = list(ddgs.images(query, safesearch='Moderate', max_results=10))
                        for img in image_results:
                            if img and 'image' in img:
                                images.append(img['image'])
                        print(f"[DuckDuckGo] Found {len(images)} images for '{query}'")
                    except Exception as e:
                        print(f"[DuckDuckGo] Error fetching images: {e}")
                    
                    return {
                        "source": "DuckDuckGo",
                        "text": first_result['body'],
                        "images": images
                    }
        return None
    except Exception as e:
        print(f"DuckDuckGo error: {type(e).__name__}: {e}")
        return None


def should_use_duckduckgo_first(query):
    """Determine if DuckDuckGo should be searched first"""
    keywords = ["top", "best", "latest", "news", "today", "update", "new"]
    for word in keywords:
        if word in query.lower():
            return True
    return False


def detect_conversational_intents(query):
    intents_found = {}
    query_lower = query.lower()

    for pattern, intent in patterns_data.items():
        if "*" not in pattern:
            if re.search(rf"\b{re.escape(pattern)}\b", query_lower):
                if intent not in intents_found:
                    intents_found[intent] = pattern

    return intents_found


def is_pure_conversational_query(query, detected_intents):
    remaining = query.lower()

    for phrase in set(detected_intents.values()):
        remaining = re.sub(rf"\b{re.escape(phrase)}\b", " ", remaining)

    remaining = re.sub(r"[^a-z0-9\s]", " ", remaining)
    remaining = re.sub(r"\s+", " ", remaining).strip()
    return remaining == ""


def get_random_intent(intent_key):
    options = dictionary_data.get(intent_key, {}).get("options", [])
    if options:
        return random.choice(options)
    return None


def generate_combined_response(detected_intents):
    name = memory_data.get("user_profile", {}).get("name", "there")
    responses = []

    greeting_word = detected_intents.get("greeting")
    status_phrase = detected_intents.get("status_check")
    
    # 🔹 GREETING ONLY
    if greeting_word and not status_phrase:
        #greeting response + name
        greeting_options = dictionary_data.get("greeting", {}).get("options", ["Hi"])
        filtered = [g for g in greeting_options if g.lower() != greeting_word.lower()]
        chosen = random.choice(filtered) if filtered else "Hi"
        responses.append(f"{chosen} {name}! 😊")
        #working on any response
        assist = dictionary_data.get("assist_prompt", {}).get("options", ["How can I assist you today?"])
        filtered_assist = [a for a in assist if a.lower() != "how can i assist you today?"]
        assist_chosen = random.choice(filtered_assist) if filtered_assist else "How can I assist you today?"
        responses.append(assist_chosen)

    # 🔹 STATUS ONLY
    elif status_phrase and not greeting_word:
        #status response + name + follow-up
        status_response = dictionary_data.get("status_check", {}).get("options", ["I'm doing great"])
        filtered = [s for s in status_response if s.lower() != status_phrase.lower()]
        chosen = random.choice(filtered) if filtered else "I'm doing great"
        assist_status = dictionary_data.get("status_followup", {}).get("options", ["How about you?"])
        filtered_status_assist = [a for a in assist_status if a.lower() != "how about you?"]
        assist_status_chosen = random.choice(filtered_status_assist) if filtered_status_assist else "How about you?"
        responses.append(f"{chosen} {name}! {assist_status_chosen}")
        #working on any response
        assist = dictionary_data.get("assist_prompt", {}).get("options", ["How can I assist you today?"])
        filtered_assist = [a for a in assist if a.lower() != "how can i assist you today?"]
        assist_chosen = random.choice(filtered_assist) if filtered_assist else "How can I assist you today?"
        responses.append(assist_chosen)

    # 🔹 BOTH GREETING + STATUS
    elif greeting_word and status_phrase:
        #greeting response + name
        greeting_options = dictionary_data.get("greeting", {}).get("options", ["Hi"])
        filtered = [g for g in greeting_options if g.lower() != greeting_word.lower()]
        chosen = random.choice(filtered) if filtered else "Hi"
        responses.append(f"{chosen} {name} !")
        #status response + follow-up
        status_response = dictionary_data.get("status_check", {}).get("options", ["I'm doing great"])
        filtered_status = [s for s in status_response if s.lower() != status_phrase.lower()]
        chosen_status = random.choice(filtered_status) if filtered_status else "I'm doing great"
        assist_status = dictionary_data.get("status_followup", {}).get("options", ["How about you?"])
        filtered_status_assist = [a for a in assist_status if a.lower() != "how about you?"]
        assist_status_chosen = random.choice(filtered_status_assist) if filtered_status_assist else "How about you?"
        responses.append(f"{chosen_status}, {assist_status_chosen} ")
        #working on any response
        assist = dictionary_data.get("assist_prompt", {}).get("options", ["How can I assist you today?"])
        filtered_assist = [a for a in assist if a.lower() != "how can i assist you today?"]
        assist_chosen = random.choice(filtered_assist) if filtered_assist else "How can I assist you today?"
        responses.append(assist_chosen)

    # 🔹 Other single intents
    for intent in detected_intents:
        if intent in ["greeting", "status_check"]:
            continue
        
        # Special handling for confirmation intent to add follow-up response
        elif intent == "confirmation":
            confirmation_response = get_random_intent("confirmation")
            followup_response = get_random_intent("confirmation_followup")

            if confirmation_response:
                responses.append(f"{confirmation_response} {followup_response}")
            continue


        response = dictionary_data.get(intent, {}).get("options", [])
        if response:
            responses.append(random.choice(response))

    # Safety fallback
    if not responses:
        return None
    
    return {
        "text": " ".join(responses),
        "images": []
    }


def process_local_brain(query):
    global dictionary_data, patterns_data, memory_data, corrections_data

    query_lower = query.lower().strip()

    # 1️⃣ Detect conversational intents
    intents = detect_conversational_intents(query)

    if intents and is_pure_conversational_query(query, intents):
        return generate_combined_response(intents)

    # 2️⃣ Corrections check
    for word in corrections_data:
        if word in query_lower:
            return {
                "source": "Local Corrections",
                "text": corrections_data[word]["correct_meaning"],
                "images": []
            }

    # 3️⃣ Dictionary fallback
    for word in dictionary_data:
        if word in query_lower:
            return {
                "source": "Local Dictionary",
                "text": dictionary_data[word]["meaning"],
                "images": []
            }

    return None


@app.route("/process_query", methods=["POST"])
@limiter.limit("30 per minute")
@require_auth
def process_query():
    """Process a user query and return information from Wikipedia or DuckDuckGo"""
    try:
        data = request.json
        if not data or 'query' not in data:
            return jsonify({"status": "error", "message": "Query required"}), 400
        
        query = data['query']
        device_id = request.headers.get('X-Device-ID', 'unknown')
        print(f"[Brain Server] Processing query: '{query}' from device: {device_id}")
        result = None

        # 🧠 First check local brain
        local_result = process_local_brain(query)
        if local_result:
            log_query_to_db(query, local_result["text"], "LocalBrain", device_id)
            return jsonify({"status": "success", "data": local_result})
        
        # Try Wikipedia first or DuckDuckGo based on query keywords
        if should_use_duckduckgo_first(query):
            print(f"[Brain Server] Trying DuckDuckGo first for: '{query}'")
            result = answer_from_duckduckgo(query)
            if not result:
                print(f"[Brain Server] DuckDuckGo failed, trying Wikipedia: '{query}'")
                result = answer_from_wikipedia(query)
        else:
            print(f"[Brain Server] Trying Wikipedia first for: '{query}'")
            result = answer_from_wikipedia(query)
            if not result:
                print(f"[Brain Server] Wikipedia failed, trying DuckDuckGo: '{query}'")
                result = answer_from_duckduckgo(query)
        
        if result:
            print(f"[Brain Server] Found result for '{query}': source={result.get('source')}")
            log_query_to_db(query, result.get('text', ''), result.get('source'), device_id)
            return jsonify({"status": "success", "data": result})
        else:
            print(f"[Brain Server] No result found for '{query}'")
            return jsonify({"status": "error", "message": "Could not find information"}), 404
    except Exception as e:
        print(f"[Brain Server] Error processing query: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/test", methods=["GET"])
def test():
    """Test endpoint to verify server is running"""
    return jsonify({"status": "ok", "message": "Brain Server is running"})


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.datetime.now().isoformat(),
        "auth_enabled": AUTH_ENABLED
    })


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/auth/register", methods=["POST"])
def register_device():
    """Register a new device and get API key"""
    try:
        # ⭐ SECURITY: Block new registrations if disabled
        if not ALLOW_NEW_REGISTRATIONS:
            print(f"[Auth] Registration attempt rejected - new registrations disabled")
            return jsonify({
                "status": "error",
                "message": "New device registrations are disabled. Contact administrator.",
                "registration_enabled": False
            }), 403
        
        data = request.json
        device_name = data.get('device_name', 'Unknown Device')
        
        api_key, device_id = add_api_key(device_name)
        
        if api_key:
            return jsonify({
                "status": "success",
                "api_key": api_key,
                "device_id": device_id,
                "device_name": device_name,
                "message": "Device registered successfully"
            })
        else:
            return jsonify({"status": "error", "message": "Failed to register device"}), 500
    except Exception as e:
        print(f"[Auth] Registration error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/execute_command", methods=["POST"])
@limiter.limit("20 per minute")
@require_auth
def execute_command():
    """Execute a command on the server (for future remote execution)"""
    try:
        data = request.json
        command = data.get('command')
        device_id = request.headers.get('X-Device-ID', 'unknown')
        
        if not command:
            return jsonify({"status": "error", "message": "Command required"}), 400
        
        print(f"[Execute] Command from {device_id}: {command}")
        log_command_to_db(command, 'execute', device_id)
        
        # Placeholder for future command execution
        # Currently just logs the command
        
        return jsonify({
            "status": "received",
            "command": command,
            "device_id": device_id
        })
    except Exception as e:
        print(f"[Execute] Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/stats", methods=["GET"])
@limiter.limit("10 per minute")
@require_auth
def get_stats():
    """Get usage statistics"""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        total_commands = c.execute("SELECT COUNT(*) FROM commands").fetchone()[0]
        total_queries = c.execute("SELECT COUNT(*) FROM queries").fetchone()[0]
        devices = c.execute("SELECT COUNT(DISTINCT device_id) FROM commands").fetchone()[0]
        
        conn.close()
        
        return jsonify({
            "status": "success",
            "total_commands": total_commands,
            "total_queries": total_queries,
            "unique_devices": devices
        })
    except Exception as e:
        print(f"[Stats] Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/test_wikipedia", methods=["POST"])
def test_wikipedia():
    """Test Wikipedia search directly"""
    try:
        query = request.json.get("query", "apple")
        print(f"[Test] Testing Wikipedia with query: '{query}'")
        result = answer_from_wikipedia(query)
        if result:
            return jsonify({"status": "success", "result": result})
        else:
            return jsonify({"status": "failed", "message": "Wikipedia returned None"}), 404
    except Exception as e:
        print(f"[Test] Wikipedia test error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/test_duckduckgo", methods=["POST"])
def test_duckduckgo():
    """Test DuckDuckGo search directly"""
    try:
        query = request.json.get("query", "apple")
        print(f"[Test] Testing DuckDuckGo with query: '{query}'")
        result = answer_from_duckduckgo(query)
        if result:
            return jsonify({"status": "success", "result": result})
        else:
            return jsonify({"status": "failed", "message": "DuckDuckGo returned None"}), 404
    except Exception as e:
        print(f"[Test] DuckDuckGo test error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/learn", methods=["POST"])
@require_auth
def learn():
    data = request.json
    word = data.get("word")
    meaning = data.get("meaning")

    if not word or not meaning:
        return jsonify({"status": "error", "message": "Word and meaning required"}), 400

    corrections_data[word.lower()] = {
        "correct_meaning": meaning,
        "corrected_by_user": True
    }

    with open(CORRECTIONS_FILE, "w") as f:
        json.dump(corrections_data, f, indent=2)

    return jsonify({"status": "success", "message": f"Learned '{word}'"})


if __name__ == "__main__":
    print("[Brain Server] Starting AI Brain Server on 0.0.0.0:5000")
    
    # Initialize database
    init_database()
    
    # Load or create API keys
    load_api_keys()
    
    if not os.path.exists(API_KEYS_FILE):
        print("[Brain Server] First run detected - creating API keys...")
        create_default_api_key()
        load_api_keys()

    dictionary_data = load_json_file(DICTIONARY_FILE, {})
    patterns_data = load_json_file(PATTERNS_FILE, {})
    memory_data = load_json_file(MEMORY_FILE, {})
    corrections_data = load_json_file(CORRECTIONS_FILE, {})
    
    print("[Brain Server] Authentication enabled ✓")
    print("[Brain Server] Database initialized ✓")
    print("[Brain Server] Ready to accept connections!")
    
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
