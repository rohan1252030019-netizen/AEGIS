# Ram Antivirus desktop app

The Electron shell starts the Next.js frontend automatically and opens it in a native desktop window. The backend API must still be running at `http://127.0.0.1:8000`.

## Development

From this directory:

```powershell
npm install
npm run electron:dev
```

## Windows installer

```powershell
npm run app:build
```

The installer is created in `release/`. Install the generated `.exe`, then start **Ram Antivirus** from the desktop or Start menu. Start the backend first with Docker Compose from the repository root:

```powershell
docker compose up -d
```