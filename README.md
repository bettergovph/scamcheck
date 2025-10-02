# 🛡️ Spam & Phishing Detection API

A free, open-source spam and phishing detection service powered by Hugging Face models and Cloudflare Workers. Completely serverless and costs **$0** to run!

## ✨ Features

- 🆓 **100% Free** - Runs on Cloudflare's free tier (100k requests/day)
- 🚀 **Fast** - Serverless edge computing with low latency
- 🤖 **AI-Powered** - Uses state-of-the-art ML models from Hugging Face
- 🌐 **Easy to Use** - Simple REST API
- 🔒 **Privacy-Focused** - No data storage, no tracking
- 🛡️ **CAPTCHA Protected** - Cloudflare Turnstile prevents abuse
- 📦 **Open Source** - MIT licensed

## 🎯 Use Cases

- Check SMS messages for spam
- Detect phishing emails
- Validate user-submitted content
- Integrate into chatbots or messaging apps
- Protect your users from scams

## 🚀 Quick Start

### 1. Prerequisites

- [Node.js](https://nodejs.org/) (v16+)
- A [Cloudflare](https://cloudflare.com) account (free)
- A [Hugging Face](https://huggingface.co) account (free)

### 2. Get Your Hugging Face Token

1. Visit <https://huggingface.co/settings/tokens>
2. Create a new token with "Read" permissions
3. Copy the token (starts with `hf_...`)

### 3. Set Up Cloudflare Turnstile (CAPTCHA)

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com) → **Turnstile**
2. Click **Add Site**
3. Enter a site name (e.g., "Spam Detector")
4. Add your domain (or use `localhost` for testing)
5. Select **Managed** widget mode
6. Copy the **Site Key** and **Secret Key**

### 4. Deploy

```bash
# Clone this repository
git clone https://github.com/bettergov/scamcheck.git
cd scamcheck

# Install dependencies
npm install

# Run the server
npm run dev

# Open the browser
open http://localhost:8787
```

### 5. Deploy

```bash
# Login to Cloudflare
npx wrangler login

# Add your Hugging Face token
npx wrangler secret put HF_TOKEN
# (paste your token when prompted)

# Add your Turnstile secret key to wrangler.toml
# Edit wrangler.toml and replace 'your-turnstile-secret-key-here' with your actual secret key

# Update test-page.html with your Turnstile site key
# Replace 'YOUR_TURNSTILE_SITE_KEY' with your actual site key

# Deploy!
npx wrangler deploy
```

You'll get a URL like: `https://scamcheck.your-subdomain.workers.dev`

## 📡 API Usage

### Endpoint

```
POST https://your-worker-url.workers.dev
```

### Request

```json
{
  "text": "URGENT: Your account has been suspended. Click here immediately!",
  "turnstileToken": "your-captcha-token-here"
}
```

**Note:** The `turnstileToken` is required and obtained from the Cloudflare Turnstile widget on your frontend.

### Response

```json
{
  "success": true,
  "text": "URGENT: Your account has been suspended. Click here immediately!",
  "predictions": [
    {
      "label": "phishing",
      "score": 0.9823
    },
    {
      "label": "safe",
      "score": 0.0177
    }
  ],
  "interpretation": {
    "isSpam": true,
    "confidence": "high",
    "confidenceScore": "98.23%",
    "message": "⚠️ HIGH RISK: This appears to be phishing/spam"
  }
}
```

### Example with curl

```bash
curl -X POST https://your-worker-url.workers.dev \
  -H "Content-Type: application/json" \
  -d '{"text": "URGENT: Click here to verify your account!"}'
```

### Example with JavaScript

```javascript
const response = await fetch('https://your-worker-url.workers.dev', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ 
    text: 'Congratulations! You won $1000!' 
  })
});

const data = await response.json();
console.log(data.interpretation.message);
```

### Example with Python

```python
import requests

response = requests.post(
    'https://your-worker-url.workers.dev',
    json={'text': 'URGENT: Your account has been compromised!'}
)

data = response.json()
print(data['interpretation']['message'])
```

## 🔧 Configuration

### Using Different Models

Edit `scamcheck.js` and change the model URL:

```javascript
const hfResponse = await fetch(
  'https://api-inference.huggingface.co/models/cybersectony/phishing-email-detection-distilbert_v2.4.1',
  // ...
);
```

**Recommended models:**

- `cybersectony/phishing-email-detection-distilbert_v2.4.1` (default)
- `mrm8488/bert-tiny-finetuned-sms-spam-detection`
- `mariagrandury/roberta-base-finetuned-sms-spam-detection`
- `elftsdmr/spam-detector`

### Rate Limiting

The free tier includes:

- ✅ 100,000 requests per day
- ✅ 10ms CPU time per request
- ✅ Worldwide edge locations

For higher limits, upgrade to Cloudflare Workers Paid plan ($5/month for 10M requests).

## 📊 Monitoring

View real-time logs:

```bash
npx wrangler tail
```

Check analytics in your [Cloudflare Dashboard](https://dash.cloudflare.com/).

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Ideas for Contributions

- [ ] Add support for multiple languages
- [ ] Implement request caching
- [ ] Add rate limiting per IP
- [ ] Support batch processing
- [ ] Create client libraries (Python, JavaScript, etc.)
- [ ] Add more detailed phishing indicators
- [ ] Improve the test UI

## 📝 License

MIT License - feel free to use this in your projects!

## 🙏 Acknowledgments

- [Hugging Face](https://huggingface.co) for the incredible model hosting
- [Cloudflare](https://cloudflare.com) for the generous free tier
- [cybersectony](https://huggingface.co/cybersectony) for the phishing detection model

## ⚠️ Disclaimer

This tool is for educational and protective purposes. Always use multiple layers of security and don't rely solely on automated detection.

## 📧 Support

- 🐛 [Report a bug](https://github.com/bettergovph/scamcheck/issues)
- 💡 [Request a feature](https://github.com/bettergovph/scamcheck/issues)
- ⭐ Star this repo if you find it useful!

---

Made with ❤️ by Jason Torres of BetterGov.ph
