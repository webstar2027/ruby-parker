# Ruby Parker

Ruby Parker is a creator membership website with a private member area, 30-day memberships, Supabase persistence/storage, Flutterwave checkout, Bitcoin payment submissions, likes, comments, account management and admin tools.

## Current payment setup

- Online checkout: Flutterwave
- Supported checkout currencies: **USD, GBP, EUR only**
- Membership price: **US$10 equivalent for 30 days**
- Bitcoin: manual verification remains available
- Naira/NGN is not offered by the website

The GBP and EUR equivalents are controlled by `FLW_GBP_PER_USD` and `FLW_EUR_PER_USD` so they can be updated without changing application code.

## Theme system

Users can choose:

- Light — white-first Ruby Parker design with pink and sky-blue accents
- Dark — dark version with the same pink/blue brand accents
- System — follows the device's light/dark preference

The selected theme is stored in the browser with local storage.

## Render environment variables

Required:

- `SITE_NAME`
- `BASE_URL`
- `SESSION_SECRET`
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`
- `BTC_ADDRESS`
- `SUPABASE_URL`
- `SUPABASE_SECRET_KEY`
- `SUPABASE_BUCKET=ruby-content`
- `FLW_SECRET_KEY`

Currency conversion controls:

- `FLW_GBP_PER_USD=0.75`
- `FLW_EUR_PER_USD=0.85`

Optional email variables:

- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_SECURE`
- `SMTP_USER`
- `SMTP_PASS`
- `MAIL_FROM`

Do not put the Supabase secret key, Flutterwave secret key, SMTP password, admin password, or session secret in GitHub or browser code.
