# Custom Homepage Feature

Pintheon now supports custom homepages that can be managed directly from the dashboard settings!

## How to Use

1. **Access Settings**: Log into your Pintheon dashboard and click the settings icon (gear icon) in the top right
2. **Find Homepage Section**: Scroll down to the "HOMEPAGE" section in settings
3. **Upload Your Website**: 
   - Click the upload icon (📤) 
   - Select a ZIP file containing your website
   - Your custom homepage will be live immediately at the root URL (/)

## File Requirements

Your ZIP file should contain:
```
your-website.zip
├── index.html (or index.htm or index.php)
├── css/
├── js/
├── images/
└── other-files/
```

## Features

- ✅ **Integrated into Dashboard**: Manage homepage from Settings section
- ✅ **Real-time Status**: See if homepage is active or not
- ✅ **Easy Upload**: Simple ZIP file upload
- ✅ **Quick Remove**: Remove homepage with one click
- ✅ **Automatic Serving**: Static files served automatically
- ✅ **Smart Routing**: Root URL (/) serves custom homepage or redirects to admin

## Status Indicators

- **Green "Active"**: Custom homepage is live
- **Orange "No custom homepage"**: Using default admin interface

## API Endpoints

- `POST /upload_homepage` - Upload ZIP file
- `POST /remove_homepage` - Remove current homepage  
- `POST /homepage_status` - Get homepage status
- `GET /` - Serves custom homepage or redirects to admin
- `GET /custom_homepage/<filename>` - Serves static files

## Security

- All operations require authentication
- Only ZIP files accepted
- Files served from dedicated directory
- Path validation prevents directory traversal

## Troubleshooting

- **"No index file found"**: Ensure ZIP contains index.html at root level
- **"Failed to extract"**: Check ZIP file integrity
- **Static files not loading**: Use relative paths in your HTML 