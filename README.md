# 🛡️ GuardianLens

**AI-Powered Social Media Safety Agent** — built for the Microsoft Agents League Hackathon 2026.

GuardianLens is an intelligent content safety agent that acts as a real-time guardian layer for social media and web browsing, protecting minors and general users from cybercrime, harmful content, grooming, phishing, and illegal redirects.

---

## 🎯 What It Does

- 🚫 **Detects cybercrime patterns** — phishing links, scam messages, grooming language, hate speech, harassment
- 👶 **Protects minors** — age-context awareness that intercepts redirects to harmful/illegal content
- 🔗 **Scans URLs in real-time** — evaluates links before a user clicks them
- 📊 **Generates safety reports** — weekly summaries for parents/guardians
- 🌐 **Multi-language support** — accessible globally
- 🧠 **Powered by Microsoft Foundry IQ** — grounded, cited threat intelligence with no hallucinations

---

## 🏗️ Architecture

```
User Input (text / URL)
        │
        ▼
┌─────────────────────┐
│   FastAPI Backend   │
│     (main.py)       │
└────────┬────────────┘
         │
   ┌─────┴──────┐
   ▼            ▼
Content      URL
Analyzer    Scanner
   │            │
   └─────┬──────┘
         ▼
   Age Guard Layer
         │
         ▼
  Foundry IQ (Microsoft)
  Knowledge Retrieval
         │
         ▼
  Safety Report Generator
         │
         ▼
  Dashboard (Parent/Guardian)
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Azure account with Foundry IQ access
- Git

### Setup (Windows)

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/guardianlens.git
cd guardianlens

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
copy .env.example .env
# Edit .env with your Azure / Foundry IQ credentials

# 5. Run the app
uvicorn api.main:app --reload
```

Open your browser at `http://localhost:8000`

---

## 📁 Project Structure

```
guardianlens/
├── agent/
│   ├── content_analyzer.py      # NLP-based safety scoring
│   ├── url_scanner.py           # Link reputation + redirect tracing
│   ├── age_guard.py             # Minor protection logic
│   └── report_generator.py      # Parent/guardian safety reports
├── foundry_iq/
│   └── knowledge_connector.py   # Microsoft Foundry IQ integration
├── api/
│   └── main.py                  # FastAPI backend
├── ui/
│   └── dashboard.html           # Guardian dashboard
├── tests/
│   ├── test_content_analyzer.py
│   ├── test_url_scanner.py
│   └── test_age_guard.py
├── .env.example
├── requirements.txt
└── README.md
```

---

## 🧠 Microsoft IQ Integration

This project uses **Foundry IQ** — Microsoft's agentic knowledge retrieval layer — to:
- Connect to threat intelligence knowledge bases
- Deliver cited, grounded answers about whether a source is dangerous
- Enforce safe search permissions
- Reduce hallucination on safety-critical decisions

---

## 🏆 Hackathon Track

- **Track**: 🎨 Creative Apps (GitHub Copilot)
- **Special awards targeted**: 🎗️ Hack for Good · 👥 Accessibility Award
- **Microsoft IQ Layer**: Foundry IQ

---

## 👤 Author

Built with ❤️ for the Microsoft Agents League Hackathon 2026.

---

## 📄 License

MIT License
