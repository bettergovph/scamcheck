/**
 * Cloudflare Worker for Spam/Phishing Detection API
 * Uses Hugging Face Inference API
 * Serves static index.html on root path and provides API on POST requests
 */

import indexHtml from './index.html';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Serve index.html on GET / (root path)
    if (request.method === 'GET' && url.pathname === '/') {
      return new Response(indexHtml, {
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