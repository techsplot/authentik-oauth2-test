const express = require('express');
const session = require('express-session');
const passport = require('passport');
const OAuth2Strategy = require('passport-oauth2');
const axios = require('axios');
require('dotenv').config();

const app = express();

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret-key',
  resave: true,
  saveUninitialized: true,
  cookie: { 
    secure: false, // Set to true in production with HTTPS
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// OAuth2 Strategy Configuration for Authentik
passport.use('authentik', new OAuth2Strategy({
  authorizationURL: `${process.env.AUTHENTIK_URL}/application/o/authorize/`,
  tokenURL: `${process.env.AUTHENTIK_URL}/application/o/token/`,
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: 'http://localhost:3000/auth/callback',
  scope: ['openid', 'profile', 'email']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    console.log('Access token received:', accessToken ? 'Yes' : 'No');
    
    // Get user info from Authentik
    const response = await axios.get(`${process.env.AUTHENTIK_URL}/application/o/userinfo/`, {
      headers: { 
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    console.log('User info received:', response.data);
    return done(null, response.data);
  } catch (error) {
    console.error('Error getting user info:', error.response?.data || error.message);
    return done(error, null);
  }
}));

// Serialize/Deserialize user for session
passport.serializeUser((user, done) => {
  console.log('Serializing user:', user.sub || user.preferred_username);
  done(null, user);
});

passport.deserializeUser((user, done) => {
  console.log('Deserializing user:', user.sub || user.preferred_username);
  done(null, user);
});

// Routes
app.get('/', (req, res) => {
  if (req.isAuthenticated()) {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Authentik Test - Success!</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
          .success { background: #d4edda; border: 1px solid #c3e6cb; padding: 20px; border-radius: 5px; }
          .user-info { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
          .logout-btn { background: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
          .logout-btn:hover { background: #c82333; }
          .protected-btn { background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-right: 10px; }
          .protected-btn:hover { background: #0056b3; }
        </style>
      </head>
      <body>
        <div class="success">
          <h1>🎉 Authentication Successful!</h1>
          <p>Your Authentik OAuth2 integration is working perfectly!</p>
        </div>
        
        <div class="user-info">
          <h2>User Information:</h2>
          <p><strong>Name:</strong> ${req.user.name || req.user.preferred_username || 'Not provided'}</p>
          <p><strong>Email:</strong> ${req.user.email || 'Not provided'}</p>
          <p><strong>Username:</strong> ${req.user.preferred_username || 'Not provided'}</p>
          <p><strong>User ID:</strong> ${req.user.sub || 'Not provided'}</p>
          <p><strong>Groups:</strong> ${req.user.groups ? req.user.groups.join(', ') : 'None'}</p>
        </div>
        
        <div>
          <a href="/protected" class="protected-btn">Test Protected Route</a>
          <a href="/logout" class="logout-btn">Logout</a>
        </div>
        
        <div style="margin-top: 30px; font-size: 12px; color: #666;">
          <h3>Debug Info:</h3>
          <pre>${JSON.stringify(req.user, null, 2)}</pre>
        </div>
      </body>
      </html>
    `);
  } else {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Authentik OAuth2 Test App</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 600px; margin: 100px auto; padding: 20px; text-align: center; }
          .login-btn { background: #28a745; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-size: 18px; }
          .login-btn:hover { background: #218838; }
          .info { background: #e9ecef; padding: 20px; border-radius: 5px; margin: 20px 0; }
        </style>
      </head>
      <body>
        <h1>Authentik OAuth2 Test Application</h1>
        <div class="info">
          <p>This application tests OAuth2 authentication with your Authentik instance.</p>
          <p><strong>Domain:</strong> ${process.env.AUTHENTIK_URL}</p>
          <p><strong>Client ID:</strong> ${process.env.CLIENT_ID}</p>
        </div>
        <a href="/auth/login" class="login-btn">🔐 Login with Authentik</a>
      </body>
      </html>
    `);
  }
});

// Login route - redirects to Authentik
app.get('/auth/login', (req, res, next) => {
  console.log('Starting authentication flow...');
  passport.authenticate('authentik', {
    scope: ['openid', 'profile', 'email']
  })(req, res, next);
});

// Callback route - handles return from Authentik
app.get('/auth/callback', (req, res, next) => {
  console.log('=== CALLBACK RECEIVED ===');
  console.log('Query params:', req.query);
  console.log('Session before auth:', req.session);
  
  passport.authenticate('authentik', (err, user, info) => {
    if (err) {
      console.error('Authentication error:', err);
      return res.redirect('/error');
    }
    
    if (!user) {
      console.error('No user returned from authentication');
      return res.redirect('/error');
    }
    
    console.log('User authenticated successfully:', user.preferred_username || user.sub);
    
    req.logIn(user, (loginErr) => {
      if (loginErr) {
        console.error('Login error:', loginErr);
        return res.redirect('/error');
      }
      
      console.log('User logged in successfully, redirecting to home');
      console.log('Session after login:', req.session);
      return res.redirect('/');
    });
  })(req, res, next);
});

// Logout route
app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    console.log('User logged out');
    res.redirect('/');
  });
});

// Protected route example
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/auth/login');
}

app.get('/protected', ensureAuthenticated, (req, res) => {
  res.json({
    message: '✅ This is a protected route - you are authenticated!',
    timestamp: new Date().toISOString(),
    user: {
      id: req.user.sub,
      name: req.user.name || req.user.preferred_username,
      email: req.user.email,
      groups: req.user.groups
    }
  });
});

// Session debug route
app.get('/debug', (req, res) => {
  res.json({
    isAuthenticated: req.isAuthenticated(),
    session: req.session,
    user: req.user || null,
    sessionID: req.sessionID
  });
});

// Error route
app.get('/error', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Authentication Error</title>
      <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 100px auto; padding: 20px; text-align: center; }
        .error { background: #f8d7da; border: 1px solid #f5c6cb; padding: 20px; border-radius: 5px; color: #721c24; }
        .retry-btn { background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
      </style>
    </head>
    <body>
      <div class="error">
        <h1>❌ Authentication Failed</h1>
        <p>There was an error during the authentication process.</p>
        <p>Please check your Authentik configuration and try again.</p>
      </div>
      <a href="/" class="retry-btn">Try Again</a>
    </body>
    </html>
  `);
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('🚀 Authentik Test App started successfully!');
  console.log(`📍 Server running on http://localhost:${PORT}`);
  console.log(`🔗 Authentik URL: ${process.env.AUTHENTIK_URL}`);
  console.log(`🔑 Client ID: ${process.env.CLIENT_ID}`);
  console.log('\n👆 Visit http://localhost:3000 to test your OAuth2 integration!');
});
