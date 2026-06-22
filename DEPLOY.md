# Deploy Messenger X to Render (free)

The whole app — server, chat, groups, admin — runs as ONE free web service.
The server also serves the website, so there is nothing else to host.

## Steps

1. **Code is already on GitHub** at `github.com/alexs5ik/messenger-x`. Nothing to do here.

2. **Sign in to Render.** Go to https://render.com and sign in with your GitHub account.

3. **Create the service from the blueprint.**
   - Click **New +** → **Blueprint**.
   - Pick the **messenger-x** repository.
   - Render reads `render.yaml` and `Dockerfile` and sets everything up. Click **Apply**.
   - (If Blueprint is not offered: **New +** → **Web Service** → pick the repo →
     it auto-detects the Dockerfile. Set Plan = Free, Health Check Path = `/health`.)

4. **Set the admin password.**
   - In the new service, open **Environment**.
   - For **MX_ADMIN_TOKEN**, enter a strong secret of your choice and save.
   - (MX_TOKEN_SECRET is generated automatically; MX_DATA_FILE is preset.)

5. **Wait for the first build** (a few minutes — it compiles Rust + builds the site).

6. **Open your app** at the `https://<name>.onrender.com` URL Render shows.
   Register by email or phone, chat, create groups, and use the admin panel
   (with the admin token you set).

## Free-tier caveats (fine for a demo)

- **Cold start:** after ~15 minutes idle the service sleeps; the next visit takes
  ~30 seconds to wake.
- **Data resets on sleep:** accounts and messages are kept in memory and saved to
  a temporary file (`/tmp`) that is wiped when the service restarts/sleeps. For a
  persistent deployment, add a database later.
