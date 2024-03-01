# whisper-api
a flask API for OpenAI's Whisper STT model

#### Example Usage

Using the Restful API

```
curl -X POST -H "X-API-KEY: your_api_key" -F "audio=@\"path/to/file.mp3\"" http://localhost:5000/api/transcribe
```

#### Docker Build

```bash
git clone https://github.com/signebedi/whisper-api.git
cd whisper-api/
sudo docker build -t whisper-api . # Please note this can take several minutes
sudo docker run -d -p 5000:5000 whisper-api
```