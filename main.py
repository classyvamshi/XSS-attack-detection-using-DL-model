from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import tensorflow as tf
import pickle
import numpy as np
import re
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import Tokenizer
import uvicorn
import os

app = FastAPI()

# Allow frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Required folders
app.mount("/static", StaticFiles(directory=r"C:\Users\hvard\Desktop\CS\CS\static"), name="static")
templates = Jinja2Templates(directory="templates")

class XSSDetector:
    def __init__(self, model_path='xss_bilstm_model.h5', tokenizer_path='tokenizer.pkl'):
        """
        Initialize the XSS detector with the trained model and tokenizer.
        """
        # Load the model
        self.model = tf.keras.models.load_model(model_path)
        
        # Initialize or load tokenizer
        if os.path.exists(tokenizer_path):
            with open(tokenizer_path, 'rb') as f:
                self.tokenizer = pickle.load(f)
        else:
            print("Tokenizer not found. Creating new tokenizer...")
            self.tokenizer = Tokenizer(num_words=10000)
            # Fit tokenizer on some basic text
            texts = [
                "<script>alert('xss')</script>",
                "<h1>Welcome</h1>",
                "<div>Hello</div>",
                "<img src=x onerror=alert('xss')>",
                "<a href='javascript:alert(1)'>Click</a>",
                "Normal text without HTML",
                "<p>Safe paragraph</p>",
                "<button onclick='submitForm()'>Submit</button>",
                "<button onclick='alert(1)'>Click me</button>"
            ]
            self.tokenizer.fit_on_texts(texts)
            # Save the tokenizer
            with open(tokenizer_path, 'wb') as f:
                pickle.dump(self.tokenizer, f)
            
        # Set maximum sequence length
        self.max_len = 100
        
        # Define safe HTML tags and attributes
        self.safe_tags = {
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'div', 'span', 'br', 
            'strong', 'em', 'i', 'b', 'u', 'a', 'img', 'ul', 'ol', 'li',
            'table', 'tr', 'td', 'th', 'thead', 'tbody', 'tfoot', 'button',
            'form', 'input', 'label', 'select', 'option', 'textarea'
        }
        
        self.safe_attributes = {
            'href', 'src', 'alt', 'title', 'class', 'id', 'style',
            'width', 'height', 'border', 'cellpadding', 'cellspacing',
            'type', 'name', 'value', 'placeholder', 'for', 'selected',
            'disabled', 'readonly', 'required', 'maxlength', 'size',
            'onclick'  # Allow onclick for simple function calls
        }
        
        # Define XSS attack patterns
        self.xss_patterns = [
            # Script tags and JavaScript
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'data:text/html',
            r'data:text/javascript',
            
            # URL parameter manipulation
            r'URLSearchParams\s*\(.*?\)\.get\s*\(',
            r'window\.location\.search',
            r'window\.location\.hash',
            r'window\.location\.href',
            
            # Dangerous JavaScript functions
            r'eval\s*\(',
            r'Function\s*\(',
            r'new\s+Function\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'execScript\s*\(',
            r'window\.execScript\s*\(',
            
            # Dangerous DOM manipulation
            r'\.innerHTML\s*=\s*[^;]+',
            r'\.outerHTML\s*=\s*[^;]+',
            r'\.insertAdjacentHTML\s*\(',
            r'\.write\s*\(',
            r'\.writeln\s*\(',
            r'document\.write\s*\(',
            r'document\.writeln\s*\(',
            r'\.appendChild\s*\(.*?\)',
            r'\.insertBefore\s*\(.*?\)',
            r'\.replaceChild\s*\(.*?\)',
            
            # Dangerous event handlers
            r'on\w+\s*=\s*["\']?.*?alert\s*\(',
            r'on\w+\s*=\s*["\']?.*?prompt\s*\(',
            r'on\w+\s*=\s*["\']?.*?confirm\s*\(',
            r'on\w+\s*=\s*["\']?.*?eval\s*\(',
            r'on\w+\s*=\s*["\']?.*?exec\s*\(',
            r'on\w+\s*=\s*["\']?.*?setTimeout\s*\(',
            r'on\w+\s*=\s*["\']?.*?setInterval\s*\(',
            
            # Dangerous attributes
            r'<.*?src\s*=\s*["\']?javascript:',
            r'<.*?href\s*=\s*["\']?javascript:',
            r'<.*?style\s*=\s*["\']?.*expression\s*\(',
            
            # Dangerous HTML elements
            r'<.*?iframe\s*.*?src\s*=',
            r'<.*?object\s*.*?data\s*=',
            r'<.*?embed\s*.*?src\s*=',
            r'<.*?svg\s*.*?onload\s*=',
            
            # Obfuscation attempts
            r'\\x[0-9a-fA-F]{2}',
            r'\\u[0-9a-fA-F]{4}',
            r'&#x[0-9a-fA-F]{2,4};',
            r'&#[0-9]{1,7};',
            
            # Common XSS payload patterns
            r'<img\s+src=x\s+onerror=',
            r'<svg\s+onload=',
            r'<body\s+onload=',
            r'<input\s+onfocus=',
            r'<select\s+onchange=',
            r'<marquee\s+onstart=',
            r'<details\s+open\s+ontoggle='
        ]
        
    def is_safe_html(self, text):
        """
        Check if the HTML is safe using rule-based detection.
        """
        # Check for XSS patterns first
        for pattern in self.xss_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return False, f"Contains XSS pattern: {pattern}"
        
        # Parse HTML tags
        tags = re.findall(r'<([^>]+)>', text)
        for tag in tags:
            # Extract tag name and attributes
            parts = re.findall(r'[\w-]+(?:\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^"\'\s>]*))?', tag)
            if not parts:
                continue
                
            tag_name = parts[0].lower()
            
            # Check if tag is safe
            if tag_name not in self.safe_tags:
                return False, f"Unsafe HTML tag: {tag_name}"
            
            # Check attributes
            for part in parts[1:]:
                if '=' in part:
                    attr = part.split('=')[0].strip().lower()
                    if attr not in self.safe_attributes:
                        return False, f"Unsafe HTML attribute: {attr}"
                    
                    # Special handling for onclick and other event handlers
                    if attr.startswith('on'):
                        value = part.split('=')[1].strip().strip('"\'')
                        # Check if event handler contains dangerous patterns
                        if re.search(r'alert\s*\(|prompt\s*\(|confirm\s*\(|eval\s*\(|exec\s*\(',
                                   value, re.IGNORECASE):
                            return False, f"Dangerous JavaScript in {attr} handler"
                        # Check for unsafe DOM manipulation
                        if re.search(r'\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\(',
                                   value, re.IGNORECASE):
                            return False, f"Unsafe DOM manipulation in {attr} handler"
                        # Check for URL parameter manipulation
                        if re.search(r'URLSearchParams|window\.location', value, re.IGNORECASE):
                            return False, f"Unsafe URL parameter manipulation in {attr} handler"
        
        return True, "Safe HTML content"
    
    def preprocess(self, text):
        """
        Preprocess the input text for prediction.
        """
        # Tokenize the text
        sequences = self.tokenizer.texts_to_sequences([text])
        
        # Pad sequences to fixed length
        padded = pad_sequences(sequences, maxlen=self.max_len, padding='post', truncating='post')
        
        return padded
    
    def predict(self, text):
        """
        Predict whether the input text is an XSS attack using both rule-based and ML-based detection.
        """
        # First check if it's safe HTML
        is_safe, reason = self.is_safe_html(text)
        if is_safe:
            return False, 1.0, reason
        
        # Check for XSS patterns
        for pattern in self.xss_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True, 1.0, f"Contains XSS pattern: {pattern}"
        
        # If not obviously safe or unsafe, use ML model
        processed_text = self.preprocess(text)
        prediction = self.model.predict(processed_text)[0][0]
        
        # Convert to boolean prediction and confidence
        is_xss = prediction > 0.5
        confidence = prediction if is_xss else 1 - prediction
        
        if is_xss:
            reason = f"ML model detected potential XSS (confidence: {confidence:.2%})"
        else:
            reason = f"ML model classified as safe (confidence: {confidence:.2%})"
        
        return is_xss, confidence, reason

# Initialize the XSS detector
try:
    detector = XSSDetector()
    print("XSS Detector initialized successfully!")
except Exception as e:
    print(f"Error initializing XSS Detector: {str(e)}")
    detector = None

# Serve the homepage
@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Prediction endpoint
@app.post("/predict")
def predict_xss(payload: dict):
    if detector is None:
        return {"error": "XSS Detector not initialized properly"}
        
    text = payload.get("sentence")
    if not text:
        return {"error": "No input provided"}

    try:
        # Use the detector to predict
        is_xss, confidence, reason = detector.predict(text)
        
        print(f"Input: {text}")
        print(f"Prediction: {'XSS' if is_xss else 'Safe'}")
        print(f"Reason: {reason}")
        print(f"Confidence: {confidence:.2%}")

        return {
            "prediction": 1 if is_xss else 0,
            "confidence": confidence,
            "reason": reason
        }
    except Exception as e:
        return {"error": str(e)}

# Run the server
if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
