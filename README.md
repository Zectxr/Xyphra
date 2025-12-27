# VirusTotal Detector

A simple React application to scan URLs and files for viruses using the VirusTotal API.

## Features

- 🔍 Scan URLs for malware and viruses
- 📁 Scan files (up to 32MB)
- 📊 Visual results with detection statistics
- 🎨 Beautiful, responsive UI

## Installation

1. Install dependencies:
```bash
npm install
```

2. Start the development server:
```bash
npm run dev
```

3. Open your browser to `http://localhost:3000`

## Usage

### Scan URL
1. Click on the "Scan URL" tab
2. Enter a URL you want to check
3. Click "Scan URL"
4. View the results

### Scan File
1. Click on the "Scan File" tab
2. Select a file (max 32MB)
3. Click "Scan File"
4. View the results

## Build for Production

```bash
npm run build
```

## Technologies Used

- React 18
- Vite
- Axios
- VirusTotal API v3
