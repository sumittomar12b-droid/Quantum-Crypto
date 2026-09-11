# 🚀 Vercel Deployment Guide
## Quantum-Inspired Cyber Threat Detection SOC (SIH 2026)

This project is configured out-of-the-box for 1-click deployment on **Vercel** using Serverless Python Functions (`@vercel/python`) and FastAPI.

---

## 📁 Deployment Configuration Files

The repository includes the following deployment-ready assets:
1. **[`vercel.json`](../vercel.json)**: Directs all HTTP routes to the serverless function handler.
2. **[`api/index.py`](../api/index.py)**: Serverless function entrypoint exposing the FastAPI ASGI app.
3. **[`requirements.txt`](../requirements.txt)**: Minimal, optimized Python dependencies automatically installed by Vercel.
4. **[`.vercelignore`](../.vercelignore)**: Excludes virtual environments (`.venv`), tests, and local build caches to keep build sizes light.

---

## 🛠️ Method 1: Deploy via GitHub & Vercel Dashboard (Recommended)

1. **Push the repository to GitHub**:
   ```bash
   git init
   git add .
   git commit -m "feat: complete quantum threat detection SOC with Vercel support"
   git branch -M main
   git remote add origin https://github.com/<your-username>/<repo-name>.git
   git push -u origin main
   ```

2. **Import into Vercel**:
   - Go to [vercel.com/new](https://vercel.com/new).
   - Select your GitHub repository.
   - Framework Preset: **Other** (Root Directory: `./`).
   - Click **Deploy**.

3. **Live Deployment**:
   - Vercel will install dependencies from `requirements.txt` and deploy your Cyber-Quantum SOC Dashboard to a production URL (e.g., `https://<your-project>.vercel.app`).

---

## 💻 Method 2: Deploy via Vercel CLI

1. **Install Vercel CLI**:
   ```bash
   npm i -g vercel
   ```

2. **Deploy from project root**:
   ```bash
   vercel
   ```
   - Follow the prompts to log in and select project scope.

3. **Deploy to Production**:
   ```bash
   vercel --prod
   ```

---

## 🌐 Deployed Endpoints

- **Web Dashboard**: `https://<project>.vercel.app/`
- **System Status API**: `https://<project>.vercel.app/api/status`
- **Protocol & Attack Simulator API**: `https://<project>.vercel.app/api/protocol/execute`
- **Audit Logs API**: `https://<project>.vercel.app/api/audit/logs`
- **Report Downloads**:
  - `https://<project>.vercel.app/api/reports/download/security_pdf`
  - `https://<project>.vercel.app/api/reports/download/performance_pdf`
  - `https://<project>.vercel.app/api/reports/download/attack_json`
