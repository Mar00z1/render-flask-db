import openai
import json
import re
import os
import bcrypt
from flask import (
    Flask, render_template, request, jsonify, 
    make_response, redirect, url_for, flash, 
    abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, 
    login_user, login_required, 
    logout_user, current_user
)
from flask_wtf.csrf import CSRFProtect
from urllib.parse import urlparse
from datetime import datetime
from sqlalchemy import text

# ==============================================
# CONFIGURACIÓN INICIAL DE FLASK Y EXTENSIONES
# ==============================================
app = Flask(__name__)

# Configuración básica
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-secreta')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicialización de extensiones
db = SQLAlchemy(app)
login_manager = LoginManager(app)
csrf = CSRFProtect(app)
openai.api_key = os.environ.get("OPENAI_API_KEY")

# ==============================================
# MODELOS DE BASE DE DATOS
# ==============================================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# ==============================================
# CONFIGURACIÓN DE AUTENTICACIÓN
# ==============================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

login_manager.login_view = 'login'
login_manager.login_message = 'Por favor inicia sesión para acceder a esta página'

# ==============================================
# FUNCIONES AUXILIARES
# ==============================================
def is_safe_url(url):
    """Valida que una URL de redirección sea segura"""
    if not url:
        return False
    parsed_url = urlparse(url)
    return not parsed_url.netloc or parsed_url.netloc == request.host

def sanitizar_markdown(texto):
    """Limpia contenido Markdown de posibles inyecciones"""
    texto = re.sub(r'<script>.*?</script>', '', texto, flags=re.DOTALL)
    texto = re.sub(r'javascript:', '', texto, flags=re.IGNORECASE)
    return texto

# ==============================================
# SISTEMA DE CHAT Y MEMORIA
# ==============================================
conversation_history = []
modo_memoria_activado = False
COMANDOS_VALIDOS = ['/clear', '/example', '/exercise', '/summary', '/help','/explicar']

system_prompt = {
    "role": "system",
    "content": (
        "Eres un profesor experto que adapta explicaciones usando ejemplos prácticos y preguntas interactivas. "
        "Usa formato Markdown para:\n"
        "- Encabezados (###)\n"
        "- **Negritas** para términos clave\n"
        "- *Cursivas* para énfasis\n"
        "- ```bloques de código```\n"
        "- ![imagen](url) para recursos visuales\n"
        "Prioriza diálogos socráticos y estructura tus respuestas en secciones claras."
    )
}

# Manejo de comandos
def procesar_comando(comando, contenido):
    prompts = {
        '/explicar': (
            f"Como profesor experto, explica: {contenido}\n"
            "Usa el historial del alumno para adaptar la explicación.\n"
            "Incluye ejemplos relevantes y preguntas interactivas.\n"
            "Formato Markdown con ecuaciones LaTeX."
        ),
        '/example': (
            f"Como profesor, muestra 3 ejemplos prácticos y originales sobre: {contenido}. "
            "Incluye: 1) Contexto realista 2) Explicación detallada 3) Aplicación práctica. "
            "Usa formato Markdown con ecuaciones cuando sea necesario."
        ),
        '/exercise': (
            f"Crea un ejercicio práctico sobre: {contenido} con: "
            "1) Enunciado claro 2) Datos relevantes 3) Guía paso a paso "
            "4) Solución matemática usando LaTeX. Estructura en secciones con ##"
        ),
        '/summary': (
            "Genera un resumen estructurado con: "
            "1) Tema principal 2) 3-5 puntos clave (###) "
            "3) Diagrama conceptual (en formato texto) 4) Ejercicio de autoevaluación. "
            "Usa viñetas y ecuaciones cuando corresponda."
        ),
        '/help': (
            "Lista detallada de comandos disponibles y su funcionamiento:\n"
            "- /clear: Reinicia la conversación\n"
            "- /example [tema]: Solicita ejemplos prácticos\n"
            "- /exercise [tema]: Genera un ejercicio con solución\n"
            "- /summary: Crea un resumen del tema\n"
            "- /help: Muestra esta ayuda\n"
            "- /explicar [tema]: Explicación detallada personalizada"
        )
    }
    return prompts.get(comando, None)

def cargar_historial():
    global conversation_history
    conversation_history = [system_prompt]
    if current_user.is_authenticated:
        messages = Message.query.filter_by(user_id=current_user.id).order_by(Message.timestamp).all()
        for msg in messages:
            conversation_history.append({"role": msg.role, "content": msg.content})

def guardar_historial():
    if current_user.is_authenticated:
        Message.query.filter_by(user_id=current_user.id).delete()
        for msg in conversation_history[1:]:
            new_msg = Message(
                user_id=current_user.id,
                role=msg['role'],
                content=msg['content']
            )
            db.session.add(new_msg)
        db.session.commit()

# ==============================================
# RUTAS DE AUTENTICACIÓN
# ==============================================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Usuario o email ya registrados', 'danger')
            return redirect(url_for('register'))
            
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registro exitoso! Por favor inicia sesión', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        identifier = request.form['identifier']
        password = request.form['password']
        
        user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
        if user and user.check_password(password):
            login_user(user)
            cargar_historial()
            next_url = request.args.get('next')
            
            if next_url and not is_safe_url(next_url):
                return abort(400)
                
            return redirect(next_url or url_for('index'))
            
        flash('Credenciales incorrectas', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sesión cerrada correctamente', 'success')
    return redirect(url_for('index'))

# ==============================================
# RUTAS PRINCIPALES DEL CHAT
# ==============================================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/chat', methods=['POST'])
@login_required
def chat():
    global conversation_history, modo_memoria_activado

    user_message = request.json.get('message', '').strip()
    if not user_message:
        return jsonify({"response": "⚠️ Mensaje inválido"}), 400

    if user_message.startswith('/'):
        comando = user_message.split()[0].lower()
        contenido = user_message[len(comando):].strip()
        
        if comando not in COMANDOS_VALIDOS:
            return jsonify({"response": f"❌ Comando no reconocido: {comando}"}), 400
            
        prompt_comando = procesar_comando(comando, contenido)
        if not prompt_comando:
            return jsonify({"response": "⚠️ Error en comando"}), 400
        
        conversation_history.append({"role": "user", "content": prompt_comando})
    else:
        conversation_history.append({"role": "user", "content": user_message})
    
    try:
        mensajes = conversation_history if modo_memoria_activado else [system_prompt, conversation_history[-1]]
        
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=mensajes,
            max_tokens=1500,
            temperature=0.3
        )

        bot_response = sanitizar_markdown(response.choices[0].message.content)
        conversation_history.append({"role": "assistant", "content": bot_response})
        guardar_historial()

        return jsonify({"response": bot_response})
    
    except Exception as e:
        app.logger.error(f"Error OpenAI: {str(e)}")
        return jsonify({"response": "⚠️ Error al procesar solicitud"}), 500

# ==============================================
# RUTAS ADICIONALES
# ==============================================
@app.route('/toggle_memoria', methods=['POST'])
@login_required
def toggle_memoria():
    global modo_memoria_activado
    modo_memoria_activado = not modo_memoria_activado
    return jsonify({
        "status": "success",
        "message": f"Modo memoria {'activado' if modo_memoria_activado else 'desactivado'}"
    })

@app.route('/export', methods=['GET'])
@login_required
def export_chat():
    chat_content = "\n".join(
        f"{msg['role'].capitalize()}: {msg['content']}" 
        for msg in conversation_history 
        if msg['role'] != 'system'
    )
    
    response = make_response(chat_content)
    response.headers["Content-Disposition"] = f"attachment; filename=chat_export_{datetime.now().strftime('%Y%m%d%H%M')}.txt"
    response.headers["Content-type"] = "text/plain"
    return response

@app.route('/resumen', methods=['GET'])
@login_required
def resumen():
    puntos_clave = [
        msg['content'] for msg in conversation_history 
        if msg['role'] == 'assistant' and '### Punto clave' in msg['content']
    ]
    
    if not puntos_clave:
        return jsonify({"response": "ℹ️ Aún no hay suficiente información para generar un resumen."})
    
    resumen = "## Resumen de aprendizaje\n" + "\n\n".join(puntos_clave)
    return jsonify({"response": resumen})

# ==============================================
# INICIALIZACIÓN DE LA BASE DE DATOS
# ==============================================
with app.app_context():
    db.create_all()

# ==============================================
# EJECUCIÓN PRINCIPAL
# ==============================================
if __name__ == '__main__':
    app.run(debug=False)






# Manejo de comandos
def procesar_comando(comando, contenido):
    prompts = {
        '/explicar': (
            f"Como profesor experto, explica: {contenido}\n"
            "Usa el historial del alumno para adaptar la explicación.\n"
            "Incluye ejemplos relevantes y preguntas interactivas.\n"
            "Formato Markdown con ecuaciones LaTeX."
        ),
        '/example': (
            f"Como profesor, muestra 3 ejemplos prácticos y originales sobre: {contenido}. "
            "Incluye: 1) Contexto realista 2) Explicación detallada 3) Aplicación práctica. "
            "Usa formato Markdown con ecuaciones cuando sea necesario."
        ),
        '/exercise': (
            f"Crea un ejercicio práctico sobre: {contenido} con: "
            "1) Enunciado claro 2) Datos relevantes 3) Guía paso a paso "
            "4) Solución matemática usando LaTeX. Estructura en secciones con ##"
        ),
        '/summary': (
            "Genera un resumen estructurado con: "
            "1) Tema principal 2) 3-5 puntos clave (###) "
            "3) Diagrama conceptual (en formato texto) 4) Ejercicio de autoevaluación. "
            "Usa viñetas y ecuaciones cuando corresponda."
        ),
        '/help': (
            "Lista detallada de comandos disponibles y su funcionamiento:\n"
            "- /clear: Reinicia la conversación\n"
            "- /example [tema]: Solicita ejemplos prácticos\n"
            "- /exercise [tema]: Genera un ejercicio con solución\n"
            "- /summary: Crea un resumen del tema\n"
            "- /help: Muestra esta ayuda\n"
            "- /explicar [tema]: Explicación detallada personalizada"
        )
    }
    return prompts.get(comando, None)