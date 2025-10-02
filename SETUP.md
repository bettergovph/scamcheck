# Spam/Phishing Detection Cloudflare Worker Setup

## Prerequisites
- Node.js installed (v16 or higher)
- A Cloudflare account (free tier works)
- A Hugging Face account and API token

## Step 1: Get Your Hugging Face Token

1. Go to https://huggingface.co/settings/tokens
2. Click "New token"
3. Give it a name (e.g., "spam-detector")
4. Select "Read" permission
5. Click "Generate token"
6. Copy the token (starts with `hf_...`)

## Step 2: Install Wrangler (Cloudflare CLI)

```bash
npm install -g wrangler
```

## Step 3: Login to Cloudflare

```bash
wrangler login
```

This will open a browser window to authenticate.

## Step 4: Create Your Project

```bash
# Create a new directory
mkdir scamcheck
cd scamcheck

# Copy the worker file
# (Copy scamcheck.js to this directory)

# Initialize the project
npm init -y
```

## Step 5: Add the Secret (HF Token)

```bash
wrangler secret put HF_TOKEN
```

When prompted, paste your Hugging Face token.

## Step 6: Deploy the Worker

```bash
wrangler deploy scamcheck.js
```

You'll get a URL like: `https://scamcheck.your-subdomain.workers.dev`

## Step 7: Test Your Worker

### Using curl:

```bash
curl -X POST https://your-worker-url.workers.dev \
  -H "Content-Type: application/json" \
  -d '{"text": "URGENT: Click here to verify your account!"}'
```

### Using the test page:

1. Open `test-page.html`
2. Update the `WORKER_URL` variable with your actual worker URL
3. Open the file in your browser
4. Test with the example buttons or your own text

## Example Response

```json
{
  "success": true,
  "text": "URGENT: Click here to verify your account!",
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

## Cloudflare Free Tier Limits

- **100,000 requests per day**
- **10ms CPU time per request**
- More than enough for testing and small projects!

## Troubleshooting

### Error: "Model is loading"
The Hugging Face model needs to "warm up" on first use. Wait 20-30 seconds and try again.

### Error: "Unauthorized"
Make sure your HF_TOKEN secret is set correctly:
```bash
wrangler secret put HF_TOKEN
```

### CORS errors
The worker includes CORS headers. If you still have issues, check that you're using the correct worker URL.

## Next Steps

1. **Add rate limiting** to prevent abuse
2. **Cache common phrases** to reduce API calls
3. **Add multiple models** for better accuracy
4. **Create a proper frontend** and deploy it
5. **Monitor usage** in the Cloudflare dashboard

## Useful Commands

```bash
# View logs
wrangler tail

# List secrets
wrangler secret list

# Delete a secret
wrangler secret delete HF_TOKEN

# Update the worker
wrangler deploy scamcheck.js
```

## Testing Different Models

You can easily swap models by changing the URL in the worker:

```javascript
'https://api-inference.huggingface.co/models/YOUR-MODEL-HERE'
```

Some other spam detection models to try:
- `mrm8488/bert-tiny-finetuned-sms-spam-detection`
- `mariagrandury/roberta-base-finetuned-sms-spam-detection`
- `elftsdmr/spam-detector`

## Cost Estimation

- **Cloudflare Workers**: FREE (up to 100k requests/day)
- **Hugging Face Inference API**: FREE (rate-limited)
- **Total**: $0 for low-medium traffic! 🎉