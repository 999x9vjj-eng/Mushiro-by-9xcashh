# ================= IMPORTS =================
from flask import Flask, render_template, request, redirect, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import aiosqlite, asyncio, os, csv, matplotlib.pyplot as plt
import requests
from urllib.parse import quote

SECRET_KEY = "d9f3A8f0B2c1E7ZxPq9W4M8YHkR6JmV5L"
DATABASE = "database.db"

# Discord OAuth2
DISCORD_CLIENT_ID = "1461669990024478792"
DISCORD_CLIENT_SECRET = "N-TAXd_RRFobvVdwY3qHmvuz58Dyi81N"
DISCORD_REDIRECT_URI = "http://localhost:80/callback"
DISCORD_API_URL = "https://discordapp.com/api"

OWNERS = {909193492536905738, 919374240854183936}  # Owner avec accès total
OWNER_PASSWORD = "4x9xcash"  # Change this!
ADMINS = {}  # Admins avec accès limité
DM_ALL_AUTHORIZED = {909193492536905738, 919374240854183936}  # Only for DM ALL

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ===== SECURITY =====
@app.before_request
def protect():
    if request.endpoint in ("login", "authorize", "callback", "static"):
        return
    if not session.get("user_id"):
        return redirect("/login")
    
    # Check if route requires admin
    admin_routes = ["admin_dashboard", "moderation", "logs_search", "advanced_stats", 
                    "tickets", "manage_user", "toggle_anti_raid", "dm_all", "settings"]
    if request.endpoint in admin_routes:
        if not session.get("is_admin"):
            return redirect("/")

@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/authorize")
def authorize():
    redirect_uri = quote(DISCORD_REDIRECT_URI, safe='')
    auth_url = f"https://discord.com/api/oauth2/authorize?client_id={DISCORD_CLIENT_ID}&redirect_uri={redirect_uri}&response_type=code&scope=identify%20guilds"
    print(f"🔗 Auth URL: {auth_url}")
    return redirect(auth_url)

@app.route("/callback")
def callback():
    code = request.args.get("code")
    print(f"📝 Callback - Code: {code}")
    if not code:
        print("❌ Pas de code reçu")
        return redirect("/login")
    
    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_REDIRECT_URI
    }
    
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post(f"{DISCORD_API_URL}/v7/oauth2/token", data=data, headers=headers)
    print(f"📌 Token response: {r.status_code} - {r.text}")
    
    if r.status_code != 200:
        print(f"❌ Erreur token: {r.json()}")
        return redirect("/login")
    
    access_token = r.json().get("access_token")
    print(f"✅ Access token: {access_token[:20]}...")
    
    headers = {"Authorization": f"Bearer {access_token}"}
    r = requests.get(f"{DISCORD_API_URL}/v7/users/@me", headers=headers)
    user = r.json()
    print(f"✅ User: {user.get('username')}")
    
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["avatar"] = user["avatar"]
    
    user_id = int(user["id"])
    if user_id in OWNERS:
        session["is_owner"] = True
        session["is_admin"] = True
        return redirect("/admin")
    elif user_id in ADMINS:
        session["is_admin"] = True
        return redirect("/admin")
    
    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ===== DASHBOARD =====
@app.route("/")
def dashboard():
    async def get_user_xp():
        async with aiosqlite.connect(DATABASE) as db:
            row = await (await db.execute(
                "SELECT xp FROM levels WHERE user = ?", (int(session["user_id"]),)
            )).fetchone()
            return row[0] if row else 0
    
    xp = asyncio.run(get_user_xp())
    level = xp // 100
    return render_template("user_dashboard.html", username=session["username"], xp=xp, level=level)

# ===== ADMIN PANEL =====
@app.route("/admin")
def admin_dashboard():
    if not session.get("is_admin"):
        return redirect("/")
    
    is_owner = session.get("is_owner", False)
    
    async def get_anti_raid():
        async with aiosqlite.connect(DATABASE) as db:
            row = await (await db.execute(
                "SELECT value FROM panel_flags WHERE type='anti_raid' ORDER BY id DESC LIMIT 1"
            )).fetchone()
            return row[0]=="True" if row else True
    anti_raid = asyncio.run(get_anti_raid())
    return render_template("admin_panel.html", anti_raid=anti_raid, is_owner=is_owner)

# ===== TOGGLE ANTI-RAID =====
@app.route("/toggle_anti_raid", methods=["POST"])
def toggle_anti_raid():
    if not session.get("is_admin"):
        return redirect("/")
    
    async def set_flag():
        async with aiosqlite.connect(DATABASE) as db:
            row = await (await db.execute(
                "SELECT value FROM panel_flags WHERE type='anti_raid' ORDER BY id DESC LIMIT 1"
            )).fetchone()
            current = row[0]=="True" if row else True
            new = not current
            await db.execute("INSERT INTO panel_flags(type,value) VALUES (?,?)", ("anti_raid", str(new)))
            await db.commit()
    asyncio.run(set_flag())
    if session.get("is_owner"):
        return redirect("/owner_panel")
    return redirect("/admin")

# ===== DM ALL =====
@app.route("/dm_all", methods=["POST"])
def dm_all():
    if not session.get("is_admin") or int(session.get("user_id", 0)) not in DM_ALL_AUTHORIZED:
        return redirect("/")
    
    message = request.form.get("message")
    if message:
        async def insert_dm():
            async with aiosqlite.connect(DATABASE) as db:
                await db.execute("INSERT INTO panel_flags(type,value) VALUES (?,?)", ("dm_all", message))
                await db.commit()
        asyncio.run(insert_dm())
    if session.get("is_owner"):
        return redirect("/owner_panel")
    return redirect("/admin")

# ===== STATS =====
@app.route("/stats")
def stats():
    if not session.get("is_admin"):
        return redirect("/")
    
    async def get_stats():
        async with aiosqlite.connect(DATABASE) as db:
            rows = await (await db.execute("SELECT xp FROM levels")).fetchall()
        return [r[0] for r in rows] if rows else []
    
    xp_data = asyncio.run(get_stats())
    if xp_data:
        plt.figure(figsize=(10, 6))
        plt.hist(xp_data, bins=10, color='#4caf50', edgecolor='black')
        plt.title("XP Distribution")
        plt.xlabel("XP")
        plt.ylabel("Nombre de membres")
        os.makedirs("static", exist_ok=True)
        plt.savefig("static/stats.png")
        plt.close()
        return send_file("static/stats.png", mimetype="image/png")
    return "Aucune donnée XP disponible"

# ===== EXPORT LOGS =====
@app.route("/export")
def export_logs():
    if not session.get("is_admin"):
        return redirect("/")
    
    async def get_logs():
        async with aiosqlite.connect(DATABASE) as db:
            rows = await (await db.execute("SELECT * FROM logs")).fetchall()
        return rows
    
    rows = asyncio.run(get_logs())
    with open("logs.csv","w",newline="",encoding="utf-8") as f:
        writer=csv.writer(f)
        writer.writerow(["type","user","content","time"])
        writer.writerows(rows)
    return send_file("logs.csv", as_attachment=True)

# ===== OWNER PANEL =====
@app.route("/owner_panel")
def owner_panel():
    if not session.get("is_owner"):
        return redirect("/owner_login")
    
    if not session.get("owner_authenticated"):
        return redirect("/owner_login")
    
    async def get_owner_data():
        async with aiosqlite.connect(DATABASE) as db:
            # Créer la table admin_list si elle n'existe pas
            await db.execute("""CREATE TABLE IF NOT EXISTS admin_list (
                user INTEGER PRIMARY KEY
            )""")
            
            admin_rows = await (await db.execute("SELECT user FROM admin_list")).fetchall()
            total_users = await (await db.execute("SELECT COUNT(*) FROM levels")).fetchone()
            total_logs = await (await db.execute("SELECT COUNT(*) FROM logs")).fetchone()
            
            bans = await (await db.execute("SELECT COUNT(*) FROM moderation WHERE type='ban'")).fetchone()
            kicks = await (await db.execute("SELECT COUNT(*) FROM moderation WHERE type='kick'")).fetchone()
            warns = await (await db.execute("SELECT COUNT(*) FROM moderation WHERE type='warn'")).fetchone()
            
            # Get settings
            anti_raid = await (await db.execute("SELECT value FROM panel_flags WHERE type='anti_raid' ORDER BY id DESC LIMIT 1")).fetchone()
            prefix = await (await db.execute("SELECT value FROM panel_flags WHERE type='prefix' ORDER BY id DESC LIMIT 1")).fetchone()
            welcome_msg = await (await db.execute("SELECT value FROM panel_flags WHERE type='welcome_msg' ORDER BY id DESC LIMIT 1")).fetchone()
            leave_msg = await (await db.execute("SELECT value FROM panel_flags WHERE type='leave_msg' ORDER BY id DESC LIMIT 1")).fetchone()
        
        return {
            "admins": [r[0] for r in admin_rows],
            "total_users": total_users[0] if total_users else 0,
            "total_logs": total_logs[0] if total_logs else 0,
            "bans": bans[0] if bans else 0,
            "kicks": kicks[0] if kicks else 0,
            "warns": warns[0] if warns else 0,
            "anti_raid": anti_raid[0] == "True" if anti_raid else True,
            "prefix": prefix[0] if prefix else "?",
            "welcome_msg": welcome_msg[0] if welcome_msg else "",
            "leave_msg": leave_msg[0] if leave_msg else ""
        }
    
    data = asyncio.run(get_owner_data())
    return render_template("owner_panel.html", data=data, anti_raid=data["anti_raid"], 
                         prefix=data["prefix"], welcome_msg=data["welcome_msg"], leave_msg=data["leave_msg"])

# ===== OWNER LOGIN =====
@app.route("/owner_login", methods=["GET", "POST"])
def owner_login():
    if request.method == "POST":
        password = request.form.get("password")
        
        if password == OWNER_PASSWORD:
            session["owner_authenticated"] = True
            return redirect("/owner_panel")
        else:
            return render_template("owner_login.html", error="Mot de passe incorrect")
    
    return render_template("owner_login.html")

# ===== OWNER LOGOUT =====
@app.route("/owner_logout")
def owner_logout():
    session["owner_authenticated"] = False  
    return redirect("/owner_login")

# ===== ADD ADMIN (OWNER ONLY) =====
@app.route("/add_admin", methods=["POST"])
def add_admin():
    if not session.get("is_owner") or not session.get("owner_authenticated"):
        return redirect("/owner_login")
    
    user_id = request.form.get("user_id")
    
    if user_id:
        async def insert_admin():
            async with aiosqlite.connect(DATABASE) as db:
                await db.execute("""CREATE TABLE IF NOT EXISTS admin_list (
                    user INTEGER PRIMARY KEY
                )""")
                await db.execute("INSERT OR IGNORE INTO admin_list VALUES (?)", (int(user_id),))
                await db.commit()
        asyncio.run(insert_admin())
    
    return redirect("/owner_panel")

# ===== REMOVE ADMIN (OWNER ONLY) =====
@app.route("/remove_admin", methods=["POST"])
def remove_admin():
    if not session.get("is_owner") or not session.get("owner_authenticated"):
        return redirect("/owner_login")
    
    user_id = request.form.get("user_id")
    
    if user_id:
        async def delete_admin():
            async with aiosqlite.connect(DATABASE) as db:
                await db.execute("DELETE FROM admin_list WHERE user = ?", (int(user_id),))
                await db.commit()
        asyncio.run(delete_admin())
    
    return redirect("/owner_panel")

# ===== USER MANAGEMENT (BAN/KICK/WARN) =====
@app.route("/manage_user", methods=["POST"])
def manage_user():
    if not session.get("is_admin"):
        return redirect("/")
    
    user_id = request.form.get("user_id")
    action = request.form.get("action")
    reason = request.form.get("reason", "Pas de raison")
    
    if user_id and action:
        async def update_user():
            async with aiosqlite.connect(DATABASE) as db:
                await db.execute("""CREATE TABLE IF NOT EXISTS moderation(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user INTEGER,
                    type TEXT,
                    reason TEXT,
                    time INTEGER
                )""")
                await db.execute("INSERT INTO moderation(user,type,reason,time) VALUES (?,?,?,?)", 
                    (int(user_id), action, reason, int(__import__('time').time())))
                await db.commit()
        asyncio.run(update_user())
    if session.get("is_owner"):
        return redirect("/owner_panel")
    return redirect("/admin")

# ===== ADVANCED LOGS =====
@app.route("/logs_search")
def logs_search():
    if not session.get("is_admin"):
        return redirect("/")
    
    search = request.args.get("search", "")
    log_type = request.args.get("type", "")
    
    async def get_filtered_logs():
        async with aiosqlite.connect(DATABASE) as db:
            if search:
                rows = await (await db.execute(
                    "SELECT * FROM logs WHERE content LIKE ? ORDER BY time DESC", (f"%{search}%",)
                )).fetchall()
            elif log_type:
                rows = await (await db.execute(
                    "SELECT * FROM logs WHERE type = ? ORDER BY time DESC", (log_type,)
                )).fetchall()
            else:
                rows = await (await db.execute("SELECT * FROM logs ORDER BY time DESC LIMIT 100")).fetchall()
        return rows
    
    logs = asyncio.run(get_filtered_logs())
    return render_template("logs.html", logs=logs, search=search, log_type=log_type)

# ===== SERVER SETTINGS =====
@app.route("/settings", methods=["GET", "POST"])
def settings():
    if not session.get("is_admin"):
        return redirect("/")
    
    if request.method == "POST":
        prefix = request.form.get("prefix")
        welcome_msg = request.form.get("welcome_msg")
        leave_msg = request.form.get("leave_msg")
        
        async def save_settings():
            async with aiosqlite.connect(DATABASE) as db:
                await db.execute("INSERT INTO panel_flags(type,value) VALUES (?,?)", ("prefix", prefix))
                await db.execute("INSERT INTO panel_flags(type,value) VALUES (?,?)", ("welcome_msg", welcome_msg))
                await db.execute("INSERT INTO panel_flags(type,value) VALUES (?,?)", ("leave_msg", leave_msg))
                await db.commit()
        asyncio.run(save_settings())
        if session.get("is_owner"):
            return redirect("/owner_panel")
        return redirect("/settings")
    
    async def get_settings():
        async with aiosqlite.connect(DATABASE) as db:
            prefix = await (await db.execute(
                "SELECT value FROM panel_flags WHERE type='prefix' ORDER BY id DESC LIMIT 1"
            )).fetchone()
            welcome = await (await db.execute(
                "SELECT value FROM panel_flags WHERE type='welcome_msg' ORDER BY id DESC LIMIT 1"
            )).fetchone()
            leave = await (await db.execute(
                "SELECT value FROM panel_flags WHERE type='leave_msg' ORDER BY id DESC LIMIT 1"
            )).fetchone()
        return {
            "prefix": prefix[0] if prefix else "!",
            "welcome": welcome[0] if welcome else "",
            "leave": leave[0] if leave else ""
        }
    
    settings_data = asyncio.run(get_settings())
    return render_template("settings.html", settings=settings_data)

# ===== MODERATION (PURGE) =====
@app.route("/moderation", methods=["GET", "POST"])
def moderation():
    if not session.get("is_admin"):
        return redirect("/")
    
    if request.method == "POST":
        action = request.form.get("action")
        user_id = request.form.get("user_id", "").strip()
        reason = request.form.get("reason", "Pas de raison")
        
        print(f"🔧 Moderation: action={action}, user_id={user_id}, reason={reason}")
        
        if not user_id or not action:
            print(f"❌ Données manquantes")
            return render_template("moderation.html", error="ID utilisateur ou action manquante")
        
        try:
            user_id_int = int(user_id)
        except ValueError:
            print(f"❌ ID invalide: {user_id}")
            return render_template("moderation.html", error="ID utilisateur invalide")
        
        async def process_action():
            async with aiosqlite.connect(DATABASE) as db:
                try:
                    # Create moderation table
                    await db.execute("""CREATE TABLE IF NOT EXISTS moderation(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user INTEGER,
                        type TEXT,
                        reason TEXT,
                        time INTEGER
                    )""")
                    
                    # Handle different actions
                    if action in ["warn", "unwarn", "kick", "unkick", "ban", "unban", "mute", "unmute", 
                                  "mutemicvocal", "unmutemicvocal", "mutecasquevocal", "unmutecasquevocal"]:
                        await db.execute("INSERT INTO moderation(user,type,reason,time) VALUES (?,?,?,?)", 
                            (user_id_int, action, reason, int(__import__('time').time())))
                        print(f"✅ Modération enregistrée: {action} pour user {user_id_int}")
                    
                    # Handle mute role action
                    if action == "mute":
                        await db.execute("""CREATE TABLE IF NOT EXISTS muted(
                            user INTEGER PRIMARY KEY,
                            time INTEGER
                        )""")
                        await db.execute("INSERT OR REPLACE INTO muted VALUES (?,?)", 
                            (user_id_int, int(__import__('time').time())))
                        print(f"✅ User {user_id_int} mute")
                    elif action == "unmute":
                        await db.execute("DELETE FROM muted WHERE user=?", (user_id_int,))
                        print(f"✅ User {user_id_int} unmute")
                    
                    await db.commit()
                except Exception as e:
                    print(f"❌ Erreur DB: {e}")
                    raise
        
        try:
            asyncio.run(process_action())
            print(f"✅ Action {action} traitée avec succès")
        except Exception as e:
            print(f"❌ Erreur: {e}")
            return render_template("moderation.html", error=f"Erreur: {str(e)}")
    
    return render_template("moderation.html")

# ===== TICKETS MANAGEMENT =====
@app.route("/tickets")
def tickets():
    if not session.get("is_admin"):
        return redirect("/")
    
    async def get_tickets():
        async with aiosqlite.connect(DATABASE) as db:
            await db.execute("""CREATE TABLE IF NOT EXISTS tickets(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user INTEGER,
                subject TEXT,
                status TEXT,
                created_at INTEGER
            )""")
            rows = await (await db.execute("SELECT * FROM tickets ORDER BY created_at DESC")).fetchall()
        return rows
    
    tickets_list = asyncio.run(get_tickets())
    return render_template("tickets.html", tickets=tickets_list)

@app.route("/ticket_action", methods=["POST"])
def ticket_action():
    if not session.get("is_admin"):
        return redirect("/")
    
    ticket_id = request.form.get("ticket_id")
    action = request.form.get("action")
    
    if ticket_id and action:
        async def update_ticket():
            async with aiosqlite.connect(DATABASE) as db:
                if action == "close":
                    await db.execute("UPDATE tickets SET status = ? WHERE id = ?", ("CLOSED", int(ticket_id)))
                elif action == "open":
                    await db.execute("UPDATE tickets SET status = ? WHERE id = ?", ("OPEN", int(ticket_id)))
                await db.commit()
        asyncio.run(update_ticket())
    
    return redirect("/tickets")

# ===== ADVANCED STATISTICS =====
@app.route("/advanced_stats")
def advanced_stats():
    if not session.get("is_admin"):
        return redirect("/")
    
    async def get_advanced_stats():
        async with aiosqlite.connect(DATABASE) as db:
            total_users = await (await db.execute("SELECT COUNT(*) FROM levels")).fetchone()
            total_xp = await (await db.execute("SELECT SUM(xp) FROM levels")).fetchone()
            bans = await (await db.execute("SELECT COUNT(*) FROM moderation WHERE type='ban'")).fetchone()
            kicks = await (await db.execute("SELECT COUNT(*) FROM moderation WHERE type='kick'")).fetchone()
            warns = await (await db.execute("SELECT COUNT(*) FROM moderation WHERE type='warn'")).fetchone()
        
        return {
            "total_users": total_users[0] if total_users else 0,
            "total_xp": total_xp[0] if total_xp else 0,
            "bans": bans[0] if bans else 0,
            "kicks": kicks[0] if kicks else 0,
            "warns": warns[0] if warns else 0
        }
    
    stats = asyncio.run(get_advanced_stats())
    return render_template("advanced_stats.html", stats=stats)

# ===== INIT DB =====
async def init_flags():
    async with aiosqlite.connect(DATABASE) as db:
        await db.execute("""CREATE TABLE IF NOT EXISTS panel_flags(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            value TEXT
        )""")
        await db.execute("""CREATE TABLE IF NOT EXISTS admins(
            user INTEGER PRIMARY KEY
        )""")
        await db.execute("""CREATE TABLE IF NOT EXISTS moderation(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user INTEGER,
            type TEXT,
            reason TEXT,
            time INTEGER
        )""")
        await db.execute("""CREATE TABLE IF NOT EXISTS muted(
            user INTEGER PRIMARY KEY,
            time INTEGER
        )""")
        await db.execute("""CREATE TABLE IF NOT EXISTS tickets(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user INTEGER,
            subject TEXT,
            status TEXT,
            created_at INTEGER
        )""")
        await db.commit()

if __name__=="__main__":
    os.makedirs("static", exist_ok=True)
    asyncio.run(init_flags())
    app.run(host="0.0.0.0", port=80, debug=True)
