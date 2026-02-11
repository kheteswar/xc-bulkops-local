# XC BulkOps - F5 XC Bulk Operations Toolbox

A local web application for performing bulk operations on F5 Distributed Cloud (XC) configurations.

## Features

- **Config Visualizer** - Interactive visualization of HTTP Load Balancers and CDN configurations
- **WAF Status Scanner** - Audit WAF modes across namespaces
- **Copy Config** - Copy Alert Receivers and Policies across tenants/namespaces

## Prerequisites

- Node.js 18+ (LTS recommended)
- npm or yarn

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Start the application
npm start
```

The app will open automatically at `http://localhost:5173`

## Architecture

```
┌─────────────────────────────────────────────────┐
│           Vite Dev Server (Port 5173)           │
│                                                 │
│  ┌─────────────┐    ┌──────────────────────┐   │
│  │ React App   │───▶│ Built-in API Proxy   │   │
│  │ (Frontend)  │    │ (/api/proxy)         │   │
│  └─────────────┘    └──────────┬───────────┘   │
│                                │               │
└────────────────────────────────┼───────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │    F5 XC API           │
                    │  (*.volterra.io)       │
                    └────────────────────────┘
```

Everything runs on a single server - the F5 XC API proxy is built into Vite's dev server as a plugin.

## Available Scripts

| Command | Description |
|---------|-------------|
| `npm start` | Start the development server |
| `npm run dev` | Same as `npm start` |
| `npm run build` | Build for production |
| `npm run preview` | Preview production build |

## Security Notes

- API tokens are stored in browser localStorage (optional)
- All F5 XC API calls are proxied through the local server
- Tokens are sent directly to F5 XC over HTTPS
- No data is sent to external services

## Project Structure

```
xc-bulkops/
├── src/
│   ├── components/       # Reusable UI components
│   ├── context/          # React context providers
│   ├── pages/            # Page components
│   ├── services/         # API client
│   ├── types/            # TypeScript definitions
│   ├── utils/            # Utility functions
│   ├── App.tsx           # Main app component
│   └── main.tsx          # Entry point
├── vite.config.ts        # Vite config with F5 XC proxy
├── package.json
└── README.md
```

## Troubleshooting

### API Connection Failed
- Verify your F5 XC tenant name is correct
- Check if your API token is valid and not expired
- Ensure you have network access to *.volterra.io

### API Token Issues
- Generate a new API token from F5 XC Console
- Navigate to: Administration → Credentials → Add Credentials
- Select "API Token" as the credential type

## License

This tool is not affiliated with or endorsed by F5, Inc. Use at your own risk.
