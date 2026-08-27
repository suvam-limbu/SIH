/**
 * Sentryl — Demo Threat Scenarios Simulator
 * Provides pre-configured, high-fidelity test cases for live demonstrations.
 */

const SENTRYL_SCENARIOS = {
  paypal_phish: {
    id: 'paypal_phish',
    title: '🚨 High-Risk Phishing (PayPal Lookalike)',
    badge: 'HIGH RISK 88%',
    sender: 'security-alerts@paypaI-security.com',
    senderName: 'PayPal Security Team',
    subject: 'Urgent: Your PayPal account has been temporarily restricted within 24 hours',
    body: 'Dear customer, We detected unauthorized login attempts to your PayPal account from an unknown device in Moscow, Russia. Immediate action is required: Please verify your account and confirm your identity within 24 hours to avoid permanent account termination. Click here to validate your credentials: http://192.168.44.12/paypal/verify-identity.php',
    urls: ['http://192.168.44.12/paypal/verify-identity.php'],
    replyTo: 'harvester-drop@anonymouse-mail.to',
    headers: 'Received-SPF: softfail\nAuthentication-Results: spf=softfail dkim=fail\nReceived: from unknown (HELO mail-spoof.de) [185.220.101.42]',
    simulatedIP: '185.220.101.42',
    geolocation: {
      ip: '185.220.101.42',
      country: 'Germany',
      city: 'Frankfurt am Main',
      isp: 'Hetzner Online (TOR / Bulletproof Exit)',
      lat: 50.1109,
      lon: 8.6821,
      is_vpn: true,
      is_tor: true
    }
  },

  bec_wire: {
    id: 'bec_wire',
    title: '⚠️ BEC / CEO Impersonation (Wire Divert)',
    badge: 'HIGH RISK 76%',
    sender: 'executive-office@company-corp.work',
    senderName: 'Sundar Pichai (CEO Office)',
    subject: 'CONFIDENTIAL: Urgent Wire Transfer Required for Project Acquisition',
    body: 'Hi Team, I am currently in a board meeting with restricted mobile access. We have an urgent confidential transaction for vendor acquisition that must be processed today. Please route an immediate payment of $45,000 to our new bank account details attached. Do not mention this to accounting until completed.',
    urls: ['https://transfer-portal.finance-docs.work/invoice_9042.pdf'],
    replyTo: 'personal-drop778@proton.me',
    headers: 'Received-SPF: none\nAuthentication-Results: spf=none dkim=none',
    simulatedIP: '45.154.255.89',
    geolocation: {
      ip: '45.154.255.89',
      country: 'Romania',
      city: 'Bucharest',
      isp: 'M247 Ltd (Hosting Provider)',
      lat: 44.4268,
      lon: 26.1025,
      is_vpn: true,
      is_tor: false
    }
  },

  ms365_creds: {
    id: 'ms365_creds',
    title: '⚠️ Credential Harvester (Microsoft 365)',
    badge: 'HIGH RISK 82%',
    sender: 'admin@micros0ft-support.xyz',
    senderName: 'IT Administrator Helpdesk',
    subject: 'Action Required: Your Microsoft 365 Password Expires in 2 Hours',
    body: 'Your organization password policy requires password renewal today. If you do not update password now, your mailbox and OneDrive will be locked. Login to verify and keep current password active: https://login.micros0ft-support.xyz/auth/login.html',
    urls: ['https://login.micros0ft-support.xyz/auth/login.html'],
    replyTo: 'admin@micros0ft-support.xyz',
    headers: 'Received-SPF: fail\nAuthentication-Results: spf=fail dkim=none',
    simulatedIP: '194.26.29.114',
    geolocation: {
      ip: '194.26.29.114',
      country: 'Netherlands',
      city: 'Amsterdam',
      isp: 'Serverius Holding B.V.',
      lat: 52.3676,
      lon: 4.9041,
      is_vpn: false,
      is_tor: false
    }
  },

  legit_google: {
    id: 'legit_google',
    title: '🛡️ Legitimate Clean Email (Google Security)',
    badge: 'SAFE 0%',
    sender: 'no-reply@accounts.google.com',
    senderName: 'Google Accounts',
    subject: 'Security alert for your linked Google Account',
    body: 'Your Google Account was recently signed in to from a new Windows device. If this was you, you don\'t need to do anything. If you don\'t recognize this activity, review your account devices at https://myaccount.google.com/notifications.',
    urls: ['https://myaccount.google.com/notifications'],
    replyTo: '',
    headers: 'Received-SPF: pass\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com',
    simulatedIP: '209.85.220.41',
    geolocation: {
      ip: '209.85.220.41',
      country: 'United States',
      city: 'Mountain View, CA',
      isp: 'Google LLC (Official Infrastructure)',
      lat: 37.4056,
      lon: -122.0775,
      is_vpn: false,
      is_tor: false
    }
  }
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = SENTRYL_SCENARIOS;
} else if (typeof window !== 'undefined') {
  window.SENTRYL_SCENARIOS = SENTRYL_SCENARIOS;
}
