# Ruby Parker

A Node/Express membership website with:
- Public landing page
- Member registration/login
- $10 / 30-day membership
- Paystack server-side transaction initialization + verification
- Bitcoin payment submission for admin review
- Admin dashboard
- Photo/video uploads
- Members-only feed

## Local setup
1. Copy `.env.example` to `.env`.
2. Set a strong `SESSION_SECRET`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD`.
3. For Paystack, add the secret key only to `.env` locally or Render Environment Variables. Never commit it.
4. Run `npm install` then `npm start`.

## Render
Build: `npm install`
Start: `npm start`
Health check: `/health`

The free Render filesystem is not durable for production uploads/database storage. For a real paid membership launch, move the database and media to persistent managed storage before relying on the free instance for long-term data.
