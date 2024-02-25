from faster_whisper import WhisperModel

# Here, we manually set the app to not retain the user audio. Eventually, we will want 
# to override these with environment variables, and set these to default values. 
WHISPER_RETAIN_AUDIO = False
WHISPER_MODEL_SIZE = "medium"
WHISPER_DEVICE="cpu"
WHISPER_COMPUTE_TYPE="int8"

# Initialize WhisperModel. Eventually, we will want to have a special way to initialize this model.
model = WhisperModel(WHISPER_MODEL_SIZE, device=WHISPER_DEVICE, compute_type=WHISPER_COMPUTE_TYPE)

def transcribe_audio(filepath:str, language="en", beam_size=5, word_timestamps=True):

        segments, info = model.transcribe(filepath, language=language, beam_size=beam_size, word_timestamps=word_timestamps)

        se = [s for s in segments]

        # Now, use `se` for further operations instead of `se`
        full_text_timestamped = " ".join([f"[{s.start}] {s.text}" for s in se])
        full_text = " ".join([str(s.text) for s in se])
        sections = [{"start": str(s.start), "end": str(s.end), "text": str(s.text)} for s in se]

        # Your dictionary now uses the list without consecutive duplicates
        text_dict = {
                "full_text_timestamped": full_text_timestamped,
                "full_text": full_text,
                "sections": sections,
        }

        return text_dict