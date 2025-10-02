/**
 * Cloudflare Worker for Spam/Phishing Detection
 * Uses Hugging Face Inference API
 */

const HTML_CONTENT = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Scam Check by BetterGov.ph</title>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; padding: 20px; }
    .container { background: white; border-radius: 20px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3); max-width: 600px; width: 100%; padding: 40px; }
    h1 { color: #333; margin-bottom: 10px; font-size: 28px; }
    .subtitle { color: #666; margin-bottom: 30px; font-size: 14px; }
    textarea { width: 100%; min-height: 150px; padding: 15px; border: 2px solid #e0e0e0; border-radius: 10px; font-size: 16px; font-family: inherit; resize: vertical; transition: border-color 0.3s; }
    textarea:focus { outline: none; border-color: #667eea; }
    button { width: 100%; padding: 15px; margin-top: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 10px; font-size: 16px; font-weight: 600; cursor: pointer; transition: transform 0.2s, box-shadow 0.2s; }
    button:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4); }
    button:active { transform: translateY(0); }
    button:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
    .result { margin-top: 30px; padding: 20px; border-radius: 10px; display: none; }
    .result.show { display: block; animation: slideIn 0.3s ease-out; }
    @keyframes slideIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
    .result.spam { background: #fee; border: 2px solid #fcc; }
    .result.safe { background: #efe; border: 2px solid #cfc; }
    .result-message { font-size: 18px; font-weight: 600; margin-bottom: 15px; }
    .result-details { font-size: 14px; color: #666; }
    .prediction-item { background: white; padding: 10px; margin: 5px 0; border-radius: 5px; display: flex; justify-content: space-between; align-items: center; }
    .prediction-label { font-weight: 600; }
    .prediction-score { color: #667eea; font-weight: 600; }
    .error { background: #fee; border: 2px solid #fcc; color: #c00; }
    .examples { margin-top: 20px; padding: 15px; background: #f5f5f5; border-radius: 10px; }
    .examples h3 { font-size: 14px; margin-bottom: 10px; color: #666; }
    .example-button { display: inline-block; padding: 8px 12px; margin: 5px 5px 5px 0; background: white; border: 1px solid #ddd; border-radius: 5px; font-size: 12px; cursor: pointer; transition: all 0.2s; }
    .example-button:hover { background: #667eea; color: white; border-color: #667eea; }
    .captcha-container { margin-top: 20px; display: flex; justify-content: center; align-items: center; min-height: 65px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ Spam/Phishing Detector</h1>
    <p class="subtitle">Test your messages for spam and phishing attempts</p>
    <textarea id="textInput" placeholder="Paste your email or SMS text here to check if it's spam or phishing...\n\nExample: 'URGENT: Your account has been suspended. Click here to verify your identity immediately!'"></textarea>
    <button id="checkButton" onclick="checkText()">Analyze Text</button>
    <div class="captcha-container">
      <div class="cf-turnstile" data-sitekey="0x4AAAAAAB4b4PFcxkn3-61f" data-callback="onTurnstileSuccess"></div>
    </div>
    <div id="result" class="result"></div>
    <div class="examples">
      <h3>Try these examples:</h3>
      <button class="example-button" onclick="setExample(0)">📱 GCash Scam</button>
      <button class="example-button" onclick="setExample(1)">📦 Delivery SMS</button>
      <button class="example-button" onclick="setExample(2)">🏦 Bank Alert</button>
      <button class="example-button" onclick="setExample(3)">₿ Crypto Scam</button>
      <button class="example-button" onclick="setExample(4)">🎁 Prize Scam</button>
      <button class="example-button" onclick="setExample(5)">💼 Job Scam</button>
      <button class="example-button" onclick="setExample(6)">✅ Legitimate</button>
    </div>
  </div>
  <script>
    const WORKER_URL = window.location.origin;
    let turnstileToken = null;
    let isSessionVerified = sessionStorage.getItem('captchaVerified') === 'true';
    function onTurnstileSuccess(token) {
      turnstileToken = token;
      sessionStorage.setItem('captchaVerified', 'true');
      isSessionVerified = true;
      const captchaContainer = document.querySelector('.captcha-container');
      if (captchaContainer) captchaContainer.style.display = 'none';
    }
    window.addEventListener('load', () => {
      if (isSessionVerified) {
        const captchaContainer = document.querySelector('.captcha-container');
        if (captchaContainer) captchaContainer.style.display = 'none';
      }
    });
    function clearSessionVerification() {
      sessionStorage.removeItem('captchaVerified');
      isSessionVerified = false;
      location.reload();
    }
    const examples = [
      "FREE MSG: GCASH ALERT! Your account will be locked due to suspicious activity. Verify now to avoid suspension. Click: gcash-verify.com/ph/account?user=09171234567 DO NOT IGNORE!",
      "LBC: Your package is held at customs. Pay PHP 250 clearance fee within 24hrs or item will be returned. Track & pay here: lbc-ph-delivery.net/track/PH47829 Reference: PKG-2024-8372",
      "BDO ALERT: Unusual transaction detected on your account ending in 4721. Amount: PHP 25,850.00. If this wasn't you, verify your account immediately at bdo-secure-online.com to block this transaction. Call 8631-8000.",
      "Hi po! I'm Sarah from CryptoWealth PH 🚀 Earn 300% returns in 30 days! Minimum investment 5,000 PHP. We have 10,000+ Filipino investors already earning daily! Join our Telegram: t.me/cryptowealthph Message ko lang boss for guaranteed passive income! Legit po ito 💯",
      "CONGRATULATIONS! Your mobile number 0917-XXX-XXXX won PHP 500,000 in the SMART Raffle Promo 2024! To claim, send full name, address, and valid ID to claimprize2024@outlook.com Reference Code: SM-PH-8374. Valid for 48 hours only!",
      "Good day! We reviewed your profile and you're qualified for our HOME-BASED DATA ENCODER position. Salary: 35,000-45,000/month, work from home, no experience needed! Send 500 PHP processing fee to GCash 09178765432 (Training Materials Fee) then we'll send your starter kit and account. Limited slots only!",
      "Hi! This is Jenny from the dentist's office. Just confirming your appointment tomorrow, January 15 at 3:00 PM with Dr. Cruz. Please arrive 10 minutes early to update your records. If you need to reschedule, please call us at 02-8234-5678. See you tomorrow!"
    ];
    function setExample(index) { document.getElementById('textInput').value = examples[index]; }
    async function checkText() {
      const textInput = document.getElementById('textInput');
      const checkButton = document.getElementById('checkButton');
      const resultDiv = document.getElementById('result');
      const text = textInput.value.trim();
      if (!text) { alert('Please enter some text to analyze'); return; }
      if (!isSessionVerified && !turnstileToken) { alert('Please complete the CAPTCHA verification'); return; }
      checkButton.disabled = true;
      checkButton.textContent = 'Analyzing...';
      resultDiv.classList.remove('show');
      try {
        const response = await fetch(WORKER_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text, turnstileToken: turnstileToken || null, sessionVerified: isSessionVerified })
        });
        const data = await response.json();
        if (data.error) throw new Error(data.error);
        displayResult(data);
      } catch (error) {
        resultDiv.className = 'result error show';
        resultDiv.innerHTML = \`<div class="result-message">❌ Error</div><div class="result-details">\${error.message}</div>\`;
      } finally {
        checkButton.disabled = false;
        checkButton.textContent = 'Analyze Text';
      }
    }
    function displayResult(data) {
      const resultDiv = document.getElementById('result');
      const interpretation = data.interpretation;
      const predictions = data.predictions;
      const isSpam = interpretation.isSpam;
      resultDiv.className = \`result \${isSpam ? 'spam' : 'safe'} show\`;
      let predictionsHTML = '';
      if (predictions && Array.isArray(predictions)) {
        predictionsHTML = predictions.map(pred => \`<div class="prediction-item"><span class="prediction-label">\${pred.label}</span><span class="prediction-score">\${(pred.score * 100).toFixed(2)}%</span></div>\`).join('');
      }
      resultDiv.innerHTML = \`<div class="result-message">\${interpretation.message}</div><div class="result-details"><strong>Confidence:</strong> \${interpretation.confidence.toUpperCase()} (\${interpretation.confidenceScore})</div>\${predictionsHTML ? \`<div class="result-details" style="margin-top: 15px;"><strong>Detailed Predictions:</strong>\${predictionsHTML}</div>\` : ''}\`;
    }
    document.getElementById('textInput').addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) checkText();
    });
  </script>
</body>
</html>`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    
    // Serve index.html on GET / (root path)
    if (request.method === 'GET' && url.pathname === '/') {
      return new Response(HTML_CONTENT, {
        headers: {
          'Content-Type': 'text/html;charset=UTF-8',
        },
      });
    }

    // Handle CORS preflight requests
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
        },
      });
    }

    // Only allow POST requests for API
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'Method not allowed' }), {
        status: 405,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    try {
      // Parse request body
      const { text, turnstileToken, sessionVerified } = await request.json();

      if (!text || typeof text !== 'string') {
        return new Response(
          JSON.stringify({ error: 'Invalid input. "text" field is required.' }),
          {
            status: 400,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*',
            },
          }
        );
      }

      // Only verify CAPTCHA on first request (when session is not yet verified)
      if (!sessionVerified) {
        // Verify Turnstile token (CAPTCHA) for new sessions
        if (!turnstileToken) {
          return new Response(
            JSON.stringify({ error: 'CAPTCHA verification required.' }),
            {
              status: 400,
              headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
              },
            }
          );
        }

        const turnstileVerified = await verifyTurnstile(turnstileToken, env.TURNSTILE_SECRET_KEY);
        
        if (!turnstileVerified) {
          return new Response(
            JSON.stringify({ error: 'CAPTCHA verification failed. Please try again.' }),
            {
              status: 403,
              headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
              },
            }
          );
        }
      }
      // If sessionVerified is true, skip CAPTCHA verification

      // Call Hugging Face Inference API
      const hfResponse = await fetch(
        'https://api-inference.huggingface.co/models/cybersectony/phishing-email-detection-distilbert_v2.4.1',
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${env.HF_TOKEN}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            inputs: text,
          }),
        }
      );

      if (!hfResponse.ok) {
        const errorText = await hfResponse.text();
        console.error('HF API Error:', errorText);

        return new Response(
          JSON.stringify({
            error: 'Hugging Face API error',
            details: errorText
          }),
          {
            status: hfResponse.status,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*',
            },
          }
        );
      }

      const result = await hfResponse.json();

      // Format response
      return new Response(
        JSON.stringify({
          success: true,
          text: text,
          predictions: result,
          // Add friendly interpretation
          interpretation: interpretResult(result),
        }),
        {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
        }
      );

    } catch (error) {
      console.error('Error:', error);
      return new Response(
        JSON.stringify({
          error: 'Internal server error',
          message: error.message
        }),
        {
          status: 500,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
        }
      );
    }
  },
};

/**
 * Interpret the classification result
 */
function interpretResult(predictions) {
  if (!Array.isArray(predictions) || predictions.length === 0) {
    return { message: 'No predictions available' };
  }

  // Handle nested array structure from Hugging Face API
  const results = Array.isArray(predictions[0]) ? predictions[0] : predictions;
  
  if (!Array.isArray(results) || results.length === 0) {
    return { message: 'No predictions available' };
  }

  console.log('Raw predictions:', predictions);

  // Map labels to their meanings
  const labelMapping = {
    'LABEL_0': 'legitimate_email',
    'LABEL_1': 'phishing_url',
    'LABEL_2': 'legitimate_url',
    'LABEL_3': 'phishing_url_alt'
  };

  // Create probability map and find highest scoring prediction
  const probabilities = {};
  let topPrediction = results[0];
  
  results.forEach(item => {
    const mappedLabel = labelMapping[item.label] || item.label;
    probabilities[mappedLabel] = item.score;
    
    if (item.score > topPrediction.score) {
      topPrediction = item;
    }
  });

  const topLabel = labelMapping[topPrediction.label] || topPrediction.label;
  const score = topPrediction.score;

  // Determine if it's phishing/spam
  const isPhishing = topLabel === 'phishing_url' || topLabel === 'phishing_url_alt';
  const isLegitimate = topLabel === 'legitimate_email' || topLabel === 'legitimate_url';

  let confidence = 'low';
  let message = '';

  if (score > 0.9) {
    confidence = 'high';
  } else if (score > 0.7) {
    confidence = 'medium';
  } else {
    confidence = 'low';
  }

  if (isPhishing) {
    if (confidence === 'high') {
      message = '⚠️ HIGH RISK: This appears to be phishing/spam';
    } else if (confidence === 'medium') {
      message = '⚠️ MODERATE RISK: This may be phishing/spam';
    } else {
      message = '⚠️ LOW RISK: Some indicators of phishing/spam detected';
    }
  } else if (isLegitimate) {
    if (confidence === 'high') {
      message = '✓ This appears to be legitimate';
    } else if (confidence === 'medium') {
      message = '✓ Likely legitimate, but with some uncertainty';
    } else {
      message = '✓ Possibly legitimate, but low confidence';
    }
  } else {
    message = '⚠️ Unable to determine classification';
  }

  return {
    isSpam: isPhishing,
    prediction: topLabel,
    confidence,
    confidenceScore: (score * 100).toFixed(2) + '%',
    message,
    allProbabilities: probabilities
  };
}

/**
 * Verify Cloudflare Turnstile token
 */
async function verifyTurnstile(token, secretKey) {
  if (!secretKey) {
    console.error('TURNSTILE_SECRET_KEY not configured');
    return false;
  }

  try {
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        secret: secretKey,
        response: token,
      }),
    });

    const data = await response.json();
    return data.success === true;
  } catch (error) {
    console.error('Turnstile verification error:', error);
    return false;
  }
}