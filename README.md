# Farhan Device Manager (Android)

Consent-based device manager for phones owned by you or explicitly authorized by you.

## Features
- Admin and Target Device modes in one app.
- Supabase email/password authentication.
- Six-digit pairing code, valid for 10 minutes.
- Device list and foreground heartbeat.
- Target-side Allow/Deny before each remote action.
- Open Android dialer, open SMS composer, launch a selected installed app, or disconnect.

## Safety limits
- Both phones must sign in with the same Supabase account.
- Keep Target Device mode open to receive requests.
- Dialer only opens; no call is placed automatically.
- SMS composer opens; target owner must review and tap Send.
- No silent SMS/call, inbox/call-log reading, camera/microphone, screen sharing, or hidden monitoring.

## Build
Push to main or run Actions > Build Android APK manually. Download artifact farhan-device-manager-debug-apk after success.

The Supabase project schema and pairing RPC were installed separately. Only the publishable key is embedded in the Android client. Never add a service-role key.
