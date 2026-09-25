# Ruby Parker

A creator membership website with a private member area, 30-day memberships, Paystack, Bitcoin verification, Supabase persistence/storage, likes, comments, account management, admin tools and optional email notifications.

## Included
- Professional responsive homepage and Ruby Parker branding
- Member registration/login and protected sessions
- Member account page with membership status and payment history
- 30-day Paystack membership with server-side verification
- Bitcoin transaction submission with admin approval
- Private Supabase Storage for photos/videos with signed URLs
- Private feed with likes, comments and image lightbox
- Admin dashboard with member/payment/post statistics
- Post deletion and Bitcoin approval
- Data backup export from the admin dashboard
- Optional SMTP welcome/payment/expiry reminder emails
- Login/registration rate limiting and CSRF protection

## Render environment variables

Required:
- SITE_NAME
- ADMIN_EMAIL
- ADMIN_PASSWORD
- SESSION_SECRET
- SUPABASE_URL
- SUPABASE_SECRET_KEY
- SUPABASE_BUCKET=ruby-content
- BTC_ADDRESS
- PAYSTACK_PUBLIC_KEY
- PAYSTACK_SECRET_KEY
- PAYSTACK_CURRENCY=USD
- PAYSTACK_AMOUNT=1000
- PAYSTACK_DISPLAY_PRICE=$10

Optional:
- BASE_URL
- MAX_UPLOAD_MB=100
- SMTP_HOST
- SMTP_PORT=587
- SMTP_SECURE=false
- SMTP_USER
- SMTP_PASS
- MAIL_FROM

Never put the Supabase secret key, Paystack secret key, SMTP password, admin password, or session secret in GitHub or browser code.

## Supabase update

After deploying this version, run the complete `schema.sql` in Supabase SQL Editor. The new `post_likes` and `comments` tables are required for the feed's social features.

## Backups

The Admin dashboard includes a data export. Keep regular copies of that export and your Supabase Storage content. The JSON export covers database records; it does not download the actual media files.
