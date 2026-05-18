# 📚 Open-Software-Library Safety Checker

A lightweight **Flask-based web application** for analyzing and visualizing the safety of open-source libraries.  
This project helps developers quickly identify risks, track vulnerabilities, and improve the security posture of their dependencies.

---

## 🚀 Features
- **Minimal Flask backend** for serving results and handling requests.
- **Responsive UI** with improved light mode theme (templates + static assets).
- **Threat visualization** via dashboard cards and flowcharts.
- **Dynamic checks** for common OSS risks.
- **Deployment ready** with Procfile and Railway integration.

---

## 📂 Project Structure

Open-Software-Library-safety-checker/
│
├── app.py                # Flask backend entry point
├── requirements.txt      # Python dependencies
├── Procfile              # Deployment config (Railway/Heroku)
├── static/               # CSS, JS, images
├── templates/            # HTML templates (Jinja2)
├── googleef147e2249f09263.html  # Google site verification
└── README.md             # Project documentation
Code


---

## ⚙️ Installation & Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/Arv1121/Open-Software-Library-safety-checker.git
   cd Open-Software-Library-safety-checker

    Install dependencies
    bash

    pip install -r requirements.txt

    Run locally
    bash

    python app.py

    Visit http://127.0.0.1:5000 in your browser.

🌐 Deployment

This project is configured for Railway and Heroku style deployments.

    Railway: Push to your Railway project and it will auto-detect Procfile.

    GitHub Pages: For frontend-only builds, serve static files via gh-pages.

🛡️ Security Checks

The app currently supports:

    Basic dependency risk assessment

    Visualization of unsafe libraries

    Theming for improved readability

Future roadmap:

    Integration with OSS Index / Snyk APIs

    Exportable reports (PDF/CSV)

    Dark mode UI

🤝 Contributing

Pull requests are welcome!
Please open an issue first to discuss major changes.
📜 License

This project is licensed under the MIT License.
Code
