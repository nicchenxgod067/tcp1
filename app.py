import os
import sys
import importlib.util
from flask import Flask, jsonify, request
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from flask_cors import CORS


def _load_flask_subapp(module_path: str, module_name: str):
    """Load a Flask app object named `app` from a Python file path, even if the path has spaces."""
    abs_path = os.path.abspath(module_path)
    module_dir = os.path.dirname(abs_path)
    if module_dir not in sys.path:
        sys.path.insert(0, module_dir)

    spec = importlib.util.spec_from_file_location(module_name, abs_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load module spec for {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "app"):
        raise AttributeError(f"Module at {module_path} does not expose a Flask `app` variable")
    return module.app


# Load sub-apps from their existing locations
jwt_app = _load_flask_subapp(os.path.join("jwt generator", "app.py"), "jwt_generator_app")
spam_app = _load_flask_subapp(os.path.join("spam friend", "app.py"), "spam_friend_app")


base = Flask(__name__)
CORS(base, origins="*", methods=["GET", "POST", "OPTIONS"])


@base.get("/")
def root_index():
    return jsonify({
        "message": "Unified service online",
        "services": {
            "jwt_generator_ui": "/jwt/",
            "jwt_generator_api": "/jwt/cloudgen_jwt",
            "friend_spam_api": "/spam/send_requests?uid=..."
        }
    })


@base.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response


# Add CORS to sub-apps
CORS(jwt_app, origins="*", methods=["GET", "POST", "OPTIONS"])
CORS(spam_app, origins="*", methods=["GET", "POST", "OPTIONS"])

# Mount both apps under prefixes
app = DispatcherMiddleware(base, {
    "/jwt": jwt_app,
    "/spam": spam_app,
})


