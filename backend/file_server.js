const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = 3001;

// Enable CORS for frontend
app.use(cors());
app.use(express.static(path.join(__dirname, '../frontend')));

// Serve files from the out directory
app.use('/out', express.static(path.join(__dirname, '../out')));

// API endpoint to get list of files in out folder
app.get('/api/reports', (req, res) => {
    const outDir = path.join(__dirname, '../out');
    
    try {
        // Check if out directory exists
        if (!fs.existsSync(outDir)) {
            return res.json([]);
        }
        
        // Read directory contents
        const files = fs.readdirSync(outDir);
        
        // Filter for report files and get file stats
        const reports = files
            .filter(file => {
                const ext = path.extname(file).toLowerCase();
                return ['.pdf', '.csv', '.xlsx', '.xls'].includes(ext);
            })
            .map(file => {
                const filePath = path.join(outDir, file);
                const stats = fs.statSync(filePath);
                return {
                    name: file,
                    size: stats.size,
                    modified: stats.mtime.toISOString(),
                    type: path.extname(file).substring(1).toLowerCase()
                };
            })
            .sort((a, b) => new Date(b.modified) - new Date(a.modified)); // Sort by newest first
        
        res.json(reports);
    } catch (error) {
        console.error('Error reading out directory:', error);
        res.status(500).json({ error: 'Failed to read reports directory' });
    }
});

app.listen(PORT, () => {
    console.log(`File server running on http://localhost:${PORT}`);
    console.log(`Reports API available at http://localhost:${PORT}/api/reports`);
});