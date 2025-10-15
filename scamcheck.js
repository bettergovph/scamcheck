/**
 * Cloudflare Worker for Spam/Phishing Detection API
 * Uses Hugging Face Inference API
 * Serves static index.html on root path and provides API on POST requests
 */

import indexHtml from './index.html';

// Configuration
const RATE_LIMIT_WINDOW = 60; // seconds
const RATE_LIMIT_MAX = 10; // requests per window
const CACHE_TTL = 300; // 5 minutes

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Serve index.html on GET / (root path)
    if (request.method === 'GET' && url.pathname === '/') {
      return new Response(indexHtml, {
        headers: {
          'Content-Type': 'text/html;charset=UTF-8',
          'Cache-Control': 'public, max-age=3600',
        },
      });
    }

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders() });
    }

    if (request.method === 'POST') {
      return handleAnalysis(request, env, ctx);
    }

    return new Response('Not Found', { status: 404 });
  },
};

async function handleAnalysis(request, env, ctx) {
  try {
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
    const { text, turnstileToken, sessionVerified } = await request.json();

    if (!text || typeof text !== 'string' || text.length < 10) {
      return jsonResponse({ error: 'Text must be at least 10 characters' }, 400);
    }

    if (text.length > 5000) {
      return jsonResponse({ error: 'Text too long (max 5000 characters)' }, 400);
    }

    // Rate limiting
    if (env.RATE_LIMITER) {
      const rateLimitKey = `ratelimit:${clientIP}`;
      const isAllowed = await checkRateLimit(env.RATE_LIMITER, rateLimitKey);
      
      if (!isAllowed) {
        return jsonResponse({ 
          error: 'Rate limit exceeded. Please wait before trying again.' 
        }, 429);
      }
    }

    // Verify CAPTCHA
    if (!sessionVerified) {
      if (!turnstileToken) {
        return jsonResponse({ error: 'CAPTCHA verification required' }, 400);
      }

      const isValid = await verifyTurnstile(turnstileToken, env.TURNSTILE_SECRET_KEY);
      if (!isValid) {
        return jsonResponse({ error: 'CAPTCHA verification failed' }, 403);
      }
    }

    // Check cache
    const cacheKey = generateCacheKey(text);
    
    if (env.CACHE) {
      const cached = await env.CACHE.get(cacheKey, 'json');
      if (cached) {
        return jsonResponse({ ...cached, cached: true });
      }
    }

    // Enhanced local analysis
    const localAnalysis = performLocalAnalysis(text);

    // Call Hugging Face API
    const hfResponse = await fetch(
      'https://api-inference.huggingface.co/models/cybersectony/phishing-email-detection-distilbert_v2.4.1',
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.HF_TOKEN}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ inputs: text }),
      }
    );

    if (!hfResponse.ok) {
      const errorText = await hfResponse.text();
      console.error('HF API Error:', errorText);
      
      const result = buildResponse(text, null, localAnalysis);
      return jsonResponse(result);
    }

    const hfResult = await hfResponse.json();
    const result = buildResponse(text, hfResult, localAnalysis);

    // Cache result
    if (env.CACHE) {
      ctx.waitUntil(
        env.CACHE.put(cacheKey, JSON.stringify(result), {
          expirationTtl: CACHE_TTL,
        })
      );
    }

    return jsonResponse(result);

  } catch (error) {
    console.error('Analysis error:', error);
    return jsonResponse({
      error: 'Internal server error',
      message: error.message,
    }, 500);
  }
}

/**
 * IMPROVED: Enhanced local phishing analysis with better false positive handling
 */
function performLocalAnalysis(text) {
  const analysis = {
    indicators: [],
    riskScore: 0,
    patterns: [],
    legitimacySignals: 0, // Track legitimate indicators
  };

  const lower = text.toLowerCase();

  // Check for legitimate indicators first
  const legitPatterns = [
    /official.*website/i,
    /contact.*support/i,
    /visit.*official/i,
    /do not (click|respond|reply)/i,
    /report.*issue/i,
    /help center/i,
    /customer service/i,
    /for your (protection|security)/i,
  ];

  legitPatterns.forEach(pattern => {
    if (pattern.test(text)) {
      analysis.legitimacySignals++;
    }
  });

  // Whitelist legitimate domains
  const legitimateDomains = [
    'gcash.com', 'paymaya.com', 'maya.ph',
    'bdo.com.ph', 'bpi.com.ph', 'metrobank.com.ph', 'unionbank.com', 'bdo.com',
    'gov.ph', 'gmail.com', 'yahoo.com', 'outlook.com',
    'facebook.com', 'twitter.com', 'instagram.com',
    'shopee.ph', 'lazada.com.ph', 'grab.com',
    'lbc.com.ph', 'jnt.com', '2go.com.ph'
  ];

  // URL analysis with whitelist
  const urlPattern = /(https?:\/\/[^\s]+)/gi;
  const urls = text.match(urlPattern) || [];
  let hasSuspiciousUrl = false;
  let hasLegitUrl = false;
  
  urls.forEach(url => {
    const urlLower = url.toLowerCase();
    
    // Check if URL is from legitimate domain
    const isLegit = legitimateDomains.some(domain => urlLower.includes(domain));
    
    if (isLegit) {
      hasLegitUrl = true;
      analysis.legitimacySignals += 2;
      return; // Skip further checks for this URL
    }

    // Suspicious TLDs (but not if from known domains)
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club'];
    if (suspiciousTLDs.some(tld => urlLower.endsWith(tld) || urlLower.includes(tld + '/'))) {
      analysis.indicators.push({
        type: 'Suspicious Domain',
        severity: 'high',
        detail: 'Uses commonly abused domain extension',
      });
      analysis.riskScore += 35;
      hasSuspiciousUrl = true;
    }

    // IP addresses in URLs
    if (/https?:\/\/\d+\.\d+\.\d+\.\d+/.test(url)) {
      analysis.indicators.push({
        type: 'IP Address URL',
        severity: 'high',
        detail: 'Uses IP address instead of domain name',
      });
      analysis.riskScore += 30;
      hasSuspiciousUrl = true;
    }

    // URL shorteners (legitimate use but suspicious in phishing context)
    const shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'shorturl'];
    if (shorteners.some(s => urlLower.includes(s))) {
      analysis.indicators.push({
        type: 'URL Shortener',
        severity: 'medium',
        detail: 'Uses link shortener',
      });
      analysis.riskScore += 10;
    }

    // Typosquatting detection
    const commonTargets = [
      { legit: 'gcash.com', variants: ['gcash-', 'gcsah', 'g-cash', 'gcas'] },
      { legit: 'bdo.com.ph', variants: ['bd0', 'bdo-', 'b-do'] },
      { legit: 'bpi.com.ph', variants: ['bpi-', 'bp1', 'b-pi'] },
      { legit: 'paymaya.com', variants: ['pay-maya', 'paymya', 'paymaya-'] },
    ];

    commonTargets.forEach(({ legit, variants }) => {
      if (variants.some(v => urlLower.includes(v)) && !urlLower.includes(legit)) {
        analysis.indicators.push({
          type: 'Typosquatting',
          severity: 'high',
          detail: `Suspicious domain similar to ${legit}`,
        });
        analysis.riskScore += 40;
        hasSuspiciousUrl = true;
      }
    });
  });

  // IMPROVED: Context-aware urgency detection
  // Only flag if combined with suspicious elements
  const urgencyWords = ['urgent', 'immediately', 'asap', 'act now', 'limited time'];
  const hasUrgency = urgencyWords.some(word => lower.includes(word));
  
  const threatWords = ['suspended', 'locked', 'blocked', 'terminated', 'expired'];
  const hasThreat = threatWords.some(word => lower.includes(word));

  // Urgency + Threat + (Suspicious URL OR Money Request) = Red flag
  if (hasUrgency && hasThreat && (hasSuspiciousUrl || lower.includes('pay') || lower.includes('send'))) {
    analysis.indicators.push({
      type: 'Urgency Tactics',
      severity: 'high',
      detail: 'Creates false sense of urgency with threats',
    });
    analysis.riskScore += 25;
  } else if (hasUrgency && hasSuspiciousUrl) {
    // Urgency with suspicious URL only
    analysis.indicators.push({
      type: 'Urgency Language',
      severity: 'medium',
      detail: 'Uses urgent language',
    });
    analysis.riskScore += 15;
  }

  // IMPROVED: Money request detection - more specific
  const explicitMoneyRequests = [
    /pay (php|₱)?\s*\d+/i,
    /send (php|₱)?\s*\d+/i,
    /transfer.*fee/i,
    /processing fee.*php/i,
    /clearance fee/i,
    /payment.*required/i,
    /deposit.*now/i,
  ];

  const hasExplicitMoneyRequest = explicitMoneyRequests.some(p => p.test(text));
  
  if (hasExplicitMoneyRequest && !hasLegitUrl) {
    analysis.indicators.push({
      type: 'Money Request',
      severity: 'high',
      detail: 'Explicitly requests money transfer or payment',
    });
    analysis.riskScore += 35;
  }

  // IMPROVED: Personal info requests - more specific
  const sensitiveInfoRequests = [
    /send.*(id|identification)/i,
    /(provide|submit|send).*(password|pin|otp|cvv)/i,
    /enter.*(password|pin code|otp)/i,
    /verify.*(card number|cvv|pin)/i,
    /(full name|complete name).*address/i,
  ];

  if (sensitiveInfoRequests.some(p => p.test(text))) {
    analysis.indicators.push({
      type: 'Sensitive Info Request',
      severity: 'high',
      detail: 'Asks for highly sensitive personal information',
    });
    analysis.riskScore += 30;
  }

  // Prize/Lottery scams (high confidence phishing)
  if (/congratulations.*(won|winner)/i.test(text) || /you (won|win).*(prize|php|₱)/i.test(text)) {
    analysis.indicators.push({
      type: 'Prize Scam',
      severity: 'high',
      detail: 'Unsolicited prize or lottery notification',
    });
    analysis.riskScore += 40;
  }

  // Too good to be true offers
  if (/earn \d+%|guaranteed (profit|income)|risk-free.*returns/i.test(text)) {
    analysis.indicators.push({
      type: 'Unrealistic Offer',
      severity: 'high',
      detail: 'Promises unrealistic financial returns',
    });
    analysis.riskScore += 30;
  }

  // Grammar/formatting issues (weaker signal)
  if (/[A-Z]{15,}/.test(text) || /!!!+/.test(text)) {
    analysis.indicators.push({
      type: 'Poor Formatting',
      severity: 'low',
      detail: 'Excessive capitalization or punctuation',
    });
    analysis.riskScore += 5;
  }

  // IMPORTANT: Reduce risk score based on legitimacy signals
  const legitimacyReduction = Math.min(analysis.legitimacySignals * 15, 50);
  analysis.riskScore = Math.max(0, analysis.riskScore - legitimacyReduction);

  return analysis;
}

/**
 * Build final response with improved logic
 */
function buildResponse(text, hfResult, localAnalysis) {
  let interpretation;

  if (hfResult && Array.isArray(hfResult[0])) {
    interpretation = interpretHFResult(hfResult[0]);
  } else {
    interpretation = interpretLocalResult(localAnalysis);
  }

  // Combine local and HF analysis intelligently
  interpretation.localIndicators = localAnalysis.indicators;
  interpretation.localRiskScore = localAnalysis.riskScore;

  // Override HF if local analysis has strong signals
  if (localAnalysis.riskScore > 60 && !interpretation.isSpam) {
    interpretation.isSpam = true;
    interpretation.confidence = 'high';
    interpretation.message = '⚠️ HIGH RISK: Multiple phishing indicators detected';
  } else if (localAnalysis.riskScore < 20 && interpretation.isSpam) {
    // Override false positive if local analysis shows legitimate
    interpretation.isSpam = false;
    interpretation.confidence = 'medium';
    interpretation.message = '✅ Likely legitimate';
  }

  return {
    success: true,
    text,
    predictions: hfResult,
    interpretation,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Interpret Hugging Face result
 */
function interpretHFResult(predictions) {
  const labelMapping = {
    'LABEL_0': 'legitimate_email',
    'LABEL_1': 'phishing_url',
    'LABEL_2': 'legitimate_url',
    'LABEL_3': 'phishing_url_alt',
  };

  const probabilities = {};
  let topPrediction = predictions[0];

  predictions.forEach(item => {
    const mappedLabel = labelMapping[item.label] || item.label;
    probabilities[mappedLabel] = item.score;
    if (item.score > topPrediction.score) {
      topPrediction = item;
    }
  });

  const topLabel = labelMapping[topPrediction.label] || topPrediction.label;
  const score = topPrediction.score;
  const isPhishing = topLabel === 'phishing_url' || topLabel === 'phishing_url_alt';

  let confidence = score > 0.85 ? 'high' : score > 0.65 ? 'medium' : 'low';
  let message;

  if (isPhishing) {
    message = confidence === 'high' ? '⚠️ HIGH RISK: This appears to be phishing/spam' :
              confidence === 'medium' ? '⚠️ MODERATE RISK: This may be phishing/spam' :
              '⚠️ LOW RISK: Some indicators detected';
  } else {
    message = confidence === 'high' ? '✅ This appears to be legitimate' :
              confidence === 'medium' ? '✅ Likely legitimate' :
              '✅ Possibly legitimate';
  }

  return {
    isSpam: isPhishing,
    prediction: topLabel,
    confidence,
    confidenceScore: (score * 100).toFixed(2) + '%',
    message,
    allProbabilities: probabilities,
  };
}

/**
 * Interpret local analysis result
 */
function interpretLocalResult(analysis) {
  const score = analysis.riskScore;
  const isSpam = score > 45;
  
  let confidence = score > 60 ? 'high' : score > 30 ? 'medium' : 'low';
  let message;

  if (isSpam) {
    message = confidence === 'high' ? '⚠️ HIGH RISK: Multiple phishing indicators' :
              '⚠️ MODERATE RISK: Some phishing indicators detected';
  } else {
    message = '✅ No significant threats detected';
  }

  return {
    isSpam,
    confidence,
    confidenceScore: score + '/100',
    message,
    method: 'local_analysis',
  };
}

/**
 * Rate limiting using KV
 */
async function checkRateLimit(kvNamespace, key) {
  const now = Math.floor(Date.now() / 1000);
  const windowKey = `${key}:${Math.floor(now / RATE_LIMIT_WINDOW)}`;

  const count = await kvNamespace.get(windowKey);
  const currentCount = count ? parseInt(count) : 0;

  if (currentCount >= RATE_LIMIT_MAX) {
    return false;
  }

  await kvNamespace.put(windowKey, (currentCount + 1).toString(), {
    expirationTtl: RATE_LIMIT_WINDOW * 2,
  });

  return true;
}

/**
 * Verify Cloudflare Turnstile
 */
async function verifyTurnstile(token, secretKey) {
  if (!secretKey) {
    console.error('TURNSTILE_SECRET_KEY not configured');
    return false;
  }

  try {
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
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

function generateCacheKey(text) {
  const normalized = text.toLowerCase().trim().substring(0, 100);
  return `cache:${hashCode(normalized)}`;
}

function hashCode(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(36);
}

// CORS headers for API responses
function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(),
    },
  });
}
