# whisper-api
a flask API for OpenAI's Whisper STT model

#### Example Usage

Using the Restful API

```
curl -X POST -H "X-API-KEY: your_api_key" -F "audio=@\"path/to/file.mp3\"" http://localhost:5000/api/transcribe
```

